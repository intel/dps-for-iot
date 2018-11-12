/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include <assert.h>
#include <stdlib.h>
#include <dps/dps.h>
#include <dps/err.h>
#include <dps/dbg.h>
#include <dps/private/sha2.h>
#include <dps/compat.h>
#include <dps/private/bitvec.h>
#include <dps/private/cbor.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define MAX_HASHES  8

#if __BYTE_ORDER != __LITTLE_ENDIAN
   #define ENDIAN_SWAP
#endif

#ifdef _WIN32
static inline uint32_t COUNT_TZ(uint64_t n)
{
    uint32_t index;
    if (_BitScanForward64(&index, n)) {
        return index;
    } else {
        return 0;
    }
}
#else
#define COUNT_TZ(n)    __builtin_ctzll((chunk_t)n)
#endif

/*
 * Flag that indicates if serialized bit vector was rle encode or sent raw
 */
#define FLAG_RLE_ENCODED     0x01

/*
 * Indicates the complement of the bit vector was serialized
 */
#define FLAG_RLE_COMPLEMENT  0x02

#define SET_BIT(a, b)  (a)[(b) >> 6] |= (1ull << ((b) & 0x3F))
#define TEST_BIT(a, b) ((a)[(b) >> 6] & (1ull << ((b) & 0x3F)))
#define ROTL64(n, r)   (((n) << r) | ((n) >> (64 - r)))

#define FH_BITVECTOR_LEN  (4 * sizeof(uint64_t))

size_t DPS_BitVectorPopCount(DPS_BitVector* bv)
{
    return bv->popCount;
}

/*
 * Add a bit to the bit vector keeping the indices in ascending order
 */
static DPS_Status SetBit(DPS_BitVector* bv, uint16_t bit)
{
    uint16_t b;

    for (b = 0; b < bv->popCount; ++b) {
        /* nothing to do if the bit is already set */
        if (bv->setBits[b] == bit) {
            return DPS_OK;
        }
        if (bit < bv->setBits[b]) {
            if (bv->popCount != BITVEC_MAX_BITS) {
                memmove(&bv->setBits[b + 1], &bv->setBits[b], (bv->popCount - b) * sizeof(bv->setBits[b]));
            }
            break;
        }
    }
    if (bv->popCount == BITVEC_MAX_BITS) {
        return DPS_ERR_RESOURCES;
    } else {
        bv->setBits[b] = bit;
        ++bv->popCount;
        return DPS_OK;
    }
}

DPS_Status DPS_BitVectorBloomInsert(DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    DPS_Status status = DPS_OK;
    uint8_t h;
    uint32_t hashes[MAX_HASHES];

    assert(sizeof(hashes) == DPS_SHA2_DIGEST_LEN);

    DPS_Sha2((uint8_t*)hashes, data, len);
    /* TODO - could be optimized by first sorting the hashes */
    for (h = 0; h < DPS_CONFIG_HASHES; ++h) {
        uint32_t index = hashes[h] % DPS_CONFIG_BIT_LEN;
        status = SetBit(bv, index);
        if (status != DPS_OK) {
            break;
        }
    }
    return status;
}

static int TestBit(const DPS_BitVector* bv, uint16_t bit)
{
    uint16_t b;

    for (b = 0; b < bv->popCount; ++b) {
        if (bv->setBits[b] == bit) {
            return DPS_TRUE;
        }
        if (bv->setBits[b] > bit) {
            break;
        }
    }
    return DPS_FALSE;
}

int DPS_BitVectorBloomTest(const DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    uint8_t h;
    uint32_t hashes[MAX_HASHES];

    assert(sizeof(hashes) == DPS_SHA2_DIGEST_LEN);

    DPS_Sha2((uint8_t*)hashes, data, len);
    /* TODO - could be optimized by first sorting the hashes */
    for (h = 0; h < DPS_CONFIG_HASHES; ++h) {
        uint32_t index = hashes[h] % DPS_CONFIG_BIT_LEN;
        if (!TestBit(bv, index)) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

float DPS_BitVectorLoadFactor(DPS_BitVector* bv)
{
    return (float)((100.0 * DPS_BitVectorPopCount(bv) + 1.0) / DPS_CONFIG_BIT_LEN);
}

int DPS_BitVectorEquals(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    if (bv1->popCount != bv2->popCount) {
        return DPS_FALSE;
    } else {
        return memcmp(bv1->setBits, bv2->setBits, sizeof(bv1->setBits[0]) * bv1->popCount) == 0;
    }
}

int DPS_BitVectorIncludes(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    uint16_t b1 = 0;
    uint16_t b2 = 0;

    /* bv2 must have same or fewer bits set than bv1 */
    if (bv2->popCount > bv1->popCount) {
        return DPS_FALSE;
    }
    while ((b1 < bv1->popCount) && (b2 < bv2->popCount)) {
        if (bv2->setBits[b2] > bv1->setBits[b1]) {
            ++b1;
            continue;
        }
        if (bv2->setBits[b2] < bv1->setBits[b1]) {
            break;
        }
        ++b1;
        ++b2;
    }
    return b2 == bv2->popCount;
}

DPS_Status DPS_BitVectorFuzzyHash(DPS_FHBitVector* hash, DPS_BitVector* bv)
{
    uint16_t b;
    uint64_t s = 0;
    uint64_t p;
    uint32_t popCount = 0;

    if (!hash || !bv) {
        return DPS_ERR_NULL;
    }
    if (bv->popCount == 0) {
        memset(hash, 0, sizeof(hash));
        return DPS_OK;
    }
    /*
     * Squash the bit vector into 64 bits
     */
    for (b = 0; b < bv->popCount; ++b) {
        s |= (1ull << (bv->setBits[b] % 64));
    }
    p = s;
    p |= ROTL64(p, 7);
    p |= ROTL64(p, 31);
    hash->bits[0] = p;
    p = s;
    p |= ROTL64(p, 11);
    p |= ROTL64(p, 29);
    p |= ROTL64(p, 37);
    hash->bits[1] = p;
    p = s;
    p |= ROTL64(p, 13);
    p |= ROTL64(p, 17);
    p |= ROTL64(p, 19);
    p |= ROTL64(p, 41);
    hash->bits[2] = p;
    if (bv->popCount > 62) {
        hash->bits[3] = ~0ull;
    } else {
        hash->bits[3] = (1ull << bv->popCount) - 1;
    }
    return DPS_OK;
}

DPS_Status DPS_BitVectorUnion(DPS_BitVector* bvOut, DPS_BitVector* bv)
{
    DPS_Status status = DPS_OK;
    uint16_t b;

    for (b = 0; b < bv->popCount; ++b) {
        status = SetBit(bvOut, bv->setBits[b]);
        if (status != DPS_OK) {
            break;
        }
    }
    return status;
}

DPS_Status DPS_BitVectorIntersection(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2)
{
    DPS_Status status = DPS_OK;
    uint16_t b;

    bvOut->popCount = 0;

    for (b = 0; b < bv1->popCount; ++b) {
        if (TestBit(bv2, bv1->setBits[b])) {
            status = SetBit(bvOut, bv1->setBits[b]);
            if (status != DPS_OK) {
                break;
            }
        }
    }
    return status;
}

DPS_Status DPS_BitVectorXor(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2, int* equal)
{
    return DPS_ERR_FAILURE;
}

#define CLR_BIT8(a, b)   (a)[(b) >> 3] &= ~(1 << ((b) & 0x7))
#define SET_BIT8(a, b)   (a)[(b) >> 3] |= (1 << ((b) & 0x7))
#define TEST_BIT8(a, b) ((a)[(b) >> 3] &  (1 << ((b) & 0x7)))

/****************************************

  Run-length Encoding algorithm.

  String of 1's encode unchanged

  Strings with leading zeroes are encoded as follows:

  Count the leading zeroes.
  Compute number of bits C required to encode the count
  Write C zeroes followed by a 1
  Write out the range adusted count bits
  The trailing 1 is assumed and does not need to be encoded

  prefix        count width    range encoded
  --------------------------------------------
  01               1 bit           1 ..    2
  001              2 bit           3 ..    6
  0001             3 bit           7 ..   14
  00001            4 bit          15 ..   30
  000001           5 bit          31 ..   62
  0000001          6 bit          63 ..  126
  00000001         7 bit         127 ..  254
  000000001        8 bit         255 ..  510
  0000000001       9 bit         511 .. 1022
  00000000001     10 bit        1023 .. 2046
  000000000001    11 bit        2047 .. 4094
  0000000000001   12 bit        4095 .. 8190
  etc.

Examples:

1         ->        1        =       1
01        ->       01    0   =     010
001       ->       01    1   =     011
0001      ->      001   00   =   00100
00001     ->      001   01   =   00101
000001    ->      001   10   =   00110
0000001   ->      001   11   =   00111
00000001  ->     0001  000   =  001000
000000001 ->     0001  001   =  001001

 *****************************************/

/*
 * Compute ceil(log2(n))
 */
static uint32_t Ceil_Log2(uint16_t n)
{
    uint32_t b = 0;
    if (n & 0xFF00) {
        n >>= 8;  b += 8;
    }
    if (n & 0x00F0) {
        n >>= 4;  b += 4;
    }
    if (n & 0x000C) {
        n >>= 2;  b += 2;
    }
    if (n & 0x0002) {
        n >>= 1;  b += 1;
    }
    return b;
}


static size_t RLELen(DPS_BitVector* bv)
{
    uint16_t b;
    size_t rleSize = 0;
    uint16_t prevBit = 0;

    for (b = 0; b < bv->popCount; ++b) {
        /*
         * Length of the zero run
         */
        uint16_t num0 = bv->setBits[b] - prevBit;
        /*
         * Size of the length field
         */
        size_t sz = Ceil_Log2(num0 + 1);
        /*
         * Space needed to encode the length
         */
        rleSize += 1 + 2 * sz;
        prevBit = bv->setBits[b] + 1;
    }
    return (rleSize + 7) / 8;
}

static void RunLengthEncode(DPS_BitVector* bv, uint8_t* rle, size_t len)
{
    uint16_t b;
    size_t rleSize = 0;
    uint16_t prevBit = 0;

    /*
     * Clear the buffer so we only need to set the 1's
     */
    memset(rle, 0, len);
    for (b = 0; b < bv->popCount; ++b) {
        /*
         * Run length of consecutive zeroes
         */
        uint16_t num0 = bv->setBits[b] - prevBit;
        /*
         * Size of the length field
         */
        size_t sz = Ceil_Log2(num0 + 1);
        /*
         * Adjusted length value to write
         */
        uint32_t val = num0 - ((1 << sz) - 1);
        rleSize += sz;
        SET_BIT8(rle, rleSize);
        rleSize++;
        /*
         * Write length of the zero run - little endian
         */
        while (sz--) {
            if (val & 1) {
                SET_BIT8(rle, rleSize);
            }
            val >>= 1;
            rleSize++;
        }
        prevBit = bv->setBits[b] + 1;
    }
}

#define TOP_UP_THRESHOLD 56

static DPS_Status RunLengthDecode(uint8_t* rle, size_t rleSize, DPS_BitVector* bv, int complement)
{
    uint16_t bitPos = 0;
    uint64_t current;
    size_t currentBits = 0;
    uint16_t prevBit = 0;

    bv->popCount = 0;

    if (rleSize) {
        currentBits = 8;
        current = *rle++;
        --rleSize;
    }
    while (currentBits) {
        if (bitPos >= DPS_CONFIG_BIT_LEN) {
            return DPS_ERR_INVALID;
        }
        /*
         * Keep the current bits above the threshold where we are guaranteed
         * contiguous bits to decode the lengths below.
         */
        while (rleSize && (currentBits <= TOP_UP_THRESHOLD)) {
            current |= (((uint64_t)*rle++) << currentBits);
            currentBits += 8;
            --rleSize;
        }
        if (!current) {
            assert(rleSize == 0);
            break;
        }
        if (current & 1) {
            current >>= 1;
            --currentBits;
        } else {
            uint64_t val;
            uint64_t runLen;
            int tz = COUNT_TZ(current);

            current >>= (tz + 1);
            /*
             * We can extract the length with a mask
             */
            val = current & (((uint64_t)1 << tz) - 1);
            /*
             * The value is little-endian so we may need to do an endian swap
             */
#ifdef ENDIAN_SWAP
            val = BSWAP_64(val);
#endif
            runLen = val + (((uint64_t)1 << tz) - 1);

            currentBits -= (1 + tz * 2);
            current >>= tz;

            if (complement) {
                /* run of 1's */
                if ((bv->popCount + runLen) >= BITVEC_MAX_BITS) {
                    return DPS_ERR_RESOURCES;
                }
                while (runLen--) {
                    bv->setBits[bv->popCount++] = bitPos++;
                }
            } else {
                /* run of 0's */
                bitPos += (uint16_t)runLen;
                if (bv->popCount >= BITVEC_MAX_BITS) {
                    return DPS_ERR_RESOURCES;
                }
                bv->setBits[bv->popCount++] = bitPos++;
            }
        }
    }
    return DPS_OK;
}

DPS_Status DPS_FHBitVectorSerialize(DPS_FHBitVector* bv, DPS_TxBuffer* buffer)
{
    DPS_Status ret;
    uint8_t flags = 0;

    /*
     * Bit vector is encoded as an array of 3 items
     * [
     *    flags (uint),
     *    bit vector length (uint)
     *    compressed bit vector (bstr)
     * ]
     */
    ret = CBOR_EncodeArray(buffer, 3);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeUint(buffer, flags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeUint(buffer, FH_BITVECTOR_LEN);
    if (ret != DPS_OK) {
        return ret;
    }
#ifdef ENDIAN_SWAP
#error(TODO bit vector endian swapping not implemented)
#else
    ret = CBOR_EncodeBytes(buffer, (const uint8_t*)bv->bits, FH_BITVECTOR_LEN / 8);
#endif
    return ret;
}

DPS_Status DPS_BitVectorSerialize(DPS_BitVector* bv, DPS_TxBuffer* buffer)
{
    size_t len;
    DPS_Status ret;
    uint8_t* rle;
    uint8_t flags = FLAG_RLE_ENCODED; /* always RLE encoded in this implementation */

    /*
     * Bit vector is encoded as an array of 3 items
     * [
     *    flags (uint),
     *    bit vector length (uint)
     *    compressed bit vector (bstr)
     * ]
     */
    ret = CBOR_EncodeArray(buffer, 3);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeUint(buffer, flags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeUint(buffer, DPS_CONFIG_BIT_LEN);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Reserve space in the buffer and encode the bit vector
     */
    len = RLELen(bv);
    ret = CBOR_ReserveBytes(buffer, len, &rle);
    if (ret == DPS_OK) {
        RunLengthEncode(bv, rle, len);
    }
    return ret;
}

size_t DPS_BitVectorSerializeMaxSize(DPS_BitVector* bv)
{
    return CBOR_SIZEOF_ARRAY(3) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint32_t) + RLELen(bv);
}

DPS_Status DPS_BitVectorDeserialize(DPS_BitVector* bv, DPS_RxBuffer* buffer)
{
    DPS_Status ret;
    uint64_t flags;
    uint64_t len;
    size_t size;
    uint8_t* data;

    ret = CBOR_DecodeArray(buffer, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    if (size != 3) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeUint(buffer, &flags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeUint(buffer, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (len != DPS_CONFIG_BIT_LEN) {
        DPS_ERRPRINT("Deserialized bloom filter has wrong size (%d)\n", len);
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &data, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    if (flags & FLAG_RLE_ENCODED) {
        ret = RunLengthDecode(data, size, bv, (flags & FLAG_RLE_COMPLEMENT));
    } else if (size == DPS_CONFIG_BIT_LEN / 8) {
        /*
         * TODO -  Not run-length encoded so probably has too many bits set, but try anyway
         */
        ret = DPS_ERR_RESOURCES;
    } else {
        DPS_ERRPRINT("Deserialized bloom filter has wrong length\n");
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void DPS_BitVectorDup(DPS_BitVector* dst, DPS_BitVector* src)
{
    memcpy(dst->setBits, src->setBits, sizeof(src->setBits[0]) * src->popCount);
    dst->popCount = src->popCount;
}

int DPS_BitVectorIsClear(DPS_BitVector* bv)
{
    return bv->popCount == 0;
}

void DPS_BitVectorClear(DPS_BitVector* bv)
{
    bv->popCount = 0;
}

void DPS_BitVectorDump(DPS_BitVector* bv)
{
    uint16_t b;

    DPS_PRINT("[");
    for (b = 0; b < bv->popCount; ++b) {
        if (b) {
            DPS_PRINT(", ");
        }
        DPS_PRINT("%d", bv->setBits[b]);
    }
    DPS_PRINT("]\n");
}
