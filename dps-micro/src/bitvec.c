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
#include <dps/private/bitvec.h>
#include <dps/private/cbor.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

#if __BYTE_ORDER != __LITTLE_ENDIAN
   #define ENDIAN_SWAP
#endif

/*
 * Flag that indicates if serialized bit vector was rle encode or sent raw
 */
#define FLAG_RLE_ENCODED     0x01

/*
 * Indicates the complement of the bit vector was serialized
 */
#define FLAG_RLE_COMPLEMENT  0x02

/*
 * Process bit vectors in 64 bit chunks
 */
typedef uint64_t chunk_t;

#define CHUNK_SIZE (8 * sizeof(chunk_t))

#define SET_BIT(a, b)  (a)[(b) >> 6] |= (1ull << ((b) & 0x3F))
#define TEST_BIT(a, b) ((a)[(b) >> 6] & (1ull << ((b) & 0x3F)))
#define ROTL64(n, r)   (((n) << r) | ((n) >> (64 - r)))

#ifdef _WIN32
#define POPCOUNT(n)    (uint32_t)(__popcnt64((chunk_t)n))
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
#define POPCOUNT(n)    __builtin_popcountll((chunk_t)n)
#define COUNT_TZ(n)    __builtin_ctzll((chunk_t)n)
#endif

#define NUM_CHUNKS  (BITVEC_CONFIG_BIT_LEN / CHUNK_SIZE)

#define FH_BITVECTOR_LEN  (4 * sizeof(uint64_t))

#ifdef DPS_DEBUG
/*
 * This is a compressed bit dump - it groups bits to keep
 * the total output readable. This is usually more useful
 * than dumping raw 8K long bit vectors.
 */
static void CompressedBitDump(const chunk_t* data, size_t bits)
{
    size_t stride = bits <= 256 ? 2 : bits / 128;
    size_t i;
    for (i = 0; i < bits; i += stride) {
        int bit = 0;
        int j;
        for (j = 0; j < stride; ++j) {
            if (TEST_BIT(data, i + j)) {
                bit = 1;
                break;
            }
        }
        fprintf(stdout, bit ? "1" : "0");
    }
    fprintf(stdout, "\n");
}
#endif

int DPS_BitVectorIsClear(DPS_BitVector* bv)
{
    size_t i;
    for (i = 0; i < NUM_CHUNKS; ++i) {
        if (bv->bits[i]) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

uint32_t DPS_BitVectorPopCount(DPS_BitVector* bv)
{
    uint32_t popCount = 0;
    size_t i;
    for (i = 0; i < NUM_CHUNKS; ++i) {
        popCount += POPCOUNT(bv->bits[i]);
    }
    return popCount;
}

void DPS_BitVectorDup(DPS_BitVector* dst, DPS_BitVector* src)
{
    if (dst != src) {
        memcpy(dst->bits, src->bits, sizeof(src->bits));
        dst->rleSize = src->rleSize;
    }
}

void DPS_BitVectorBloomInsert(DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    uint8_t h;
    uint32_t hashes[DPS_SHA2_DIGEST_LEN];
    uint32_t index;

    DPS_Sha2((uint8_t*)hashes, data, len);
    for (h = 0; h < BITVEC_CONFIG_HASHES; ++h) {
#ifdef ENDIAN_SWAP
        index = BSWAP_32(hashes[h]) % BITVEC_CONFIG_BIT_LEN;
#else
        index = hashes[h] % BITVEC_CONFIG_BIT_LEN;
#endif
        SET_BIT(bv->bits, index);
    }
}

int DPS_BitVectorBloomTest(const DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    uint8_t h;
    uint32_t hashes[DPS_SHA2_DIGEST_LEN];
    uint32_t index;

    DPS_Sha2((uint8_t*)hashes, data, len);
    for (h = 0; h < BITVEC_CONFIG_HASHES; ++h) {
#ifdef ENDIAN_SWAP
        index = BSWAP_32(hashes[h]) % BITVEC_CONFIG_BIT_LEN;
#else
        index = hashes[h] % BITVEC_CONFIG_BIT_LEN;
#endif
        if (!TEST_BIT(bv->bits, index)) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

float DPS_BitVectorLoadFactor(DPS_BitVector* bv)
{
    return (float)((100.0 * DPS_BitVectorPopCount(bv) + 1.0) / BITVEC_CONFIG_BIT_LEN);
}

int DPS_BitVectorEquals(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    size_t i;
    const chunk_t* b1;
    const chunk_t* b2;

    if (!bv1 || !bv2) {
        return DPS_FALSE;
    }
    b1 = bv1->bits;
    b2 = bv2->bits;
    for (i = 0; i < NUM_CHUNKS; ++i, ++b1, ++b2) {
        if (*b1 != *b2) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

int DPS_BitVectorIncludes(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    size_t i;
    const chunk_t* b1;
    const chunk_t* b2;
    chunk_t b1un = 0;

    if (!bv1 || !bv2) {
        return DPS_FALSE;
    }
    b1 = bv1->bits;
    b2 = bv2->bits;
    for (i = 0; i < NUM_CHUNKS; ++i, ++b1, ++b2) {
        if ((*b1 & *b2) != *b2) {
            return DPS_FALSE;
        }
        b1un |= *b1;
    }
    return b1un != 0;
}

void DPS_BitVectorFuzzyHash(DPS_FHBitVector* hash, DPS_BitVector* bv)
{
    size_t i;
    chunk_t s = 0;
    chunk_t p;
    uint32_t popCount = 0;

    /*
     * Squash the bit vector into 64 bits
     */
    for (i = 0; i < NUM_CHUNKS; ++i) {
        chunk_t n = bv->bits[i];
        popCount += POPCOUNT(n);
        s |= n;
    }
    if (popCount == 0) {
        memset(hash, 0, sizeof(DPS_FHBitVector));
        return;
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
    if (popCount > 62) {
        hash->bits[3] = ~0ull;
    } else {
        hash->bits[3] = (1ull << popCount) - 1;
    }
    CompressedBitDump(hash->bits, FH_BITVECTOR_LEN * 8);
}

DPS_Status DPS_BitVectorUnion(DPS_BitVector* bvOut, DPS_BitVector* bv)
{
    size_t i;
    if (!bvOut || !bv) {
        return DPS_ERR_NULL;
    }
    for (i = 0; i < NUM_CHUNKS; ++i) {
        bvOut->bits[i] |= bv->bits[i];
    }
    return DPS_OK;
}

DPS_Status DPS_BitVectorIntersection(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2)
{
    size_t i;
    int nz = 0;
    if (!bvOut || !bv1 || !bv2) {
        return DPS_ERR_NULL;
    }
    for (i = 0; i < NUM_CHUNKS; ++i) {
        nz |= ((bvOut->bits[i] = bv1->bits[i] & bv2->bits[i]) != 0);
    }
    return DPS_OK;
}

DPS_Status DPS_BitVectorXor(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2, int* equal)
{
    size_t i;
    int diff = 0;
    if (!bvOut || !bv1 || !bv2) {
        return DPS_ERR_NULL;
    }

    for (i = 0; i < NUM_CHUNKS; ++i) {
        diff |= ((bvOut->bits[i] = bv1->bits[i] ^ bv2->bits[i]) != 0ull);
    }
    if (equal) {
        *equal = !diff;
    }
    return DPS_OK;
}

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


static DPS_Status RunLengthEncode(DPS_BitVector* bv, DPS_TxBuffer* buffer)
{
    DPS_Status ret;
    size_t i;
    size_t rleSize = 0;
    size_t sz;
    uint32_t num0 = 0;
    uint8_t* packed;
    chunk_t complement = bv->serializationFlags & FLAG_RLE_COMPLEMENT ? ~0 : 0;

    ret = CBOR_ReserveBytes(buffer, bv->rleSize, &packed);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Nothing to encode for empty bit vectors
     */
    if (bv->rleSize == 0) {
        return DPS_OK;
    }
    /*
     * We only need to set the 1's so clear the buffer
     */
    memset(packed, 0, bv->rleSize);

    for (i = 0; i < NUM_CHUNKS; ++i) {
        uint32_t rem0;
        chunk_t chunk = bv->bits[i] ^ complement;
        if (!chunk) {
            num0 += CHUNK_SIZE;
            continue;
        }
        rem0 = CHUNK_SIZE;
        while (chunk) {
            uint32_t val;
            int tz = COUNT_TZ(chunk);
            chunk >>= tz;
            rem0 -= tz + 1;
            num0 += tz;
            /*
             * Size of the length field
             */
            sz = Ceil_Log2(num0 + 1);
            /*
             * Adjusted length value to write
             */
            val = num0 - ((1 << sz) - 1);
            /*
             * Skip zeroes
             */
            rleSize += sz;
            SET_BIT8(packed, rleSize);
            ++rleSize;
            if ((rleSize + sz) > BITVEC_CONFIG_BIT_LEN) {
                return DPS_ERR_OVERFLOW;
            }
            /*
             * Write length of the zero run - little endian
             */
            while (sz--) {
                if (val & 1) {
                    SET_BIT8(packed, rleSize);
                }
                val >>= 1;
                ++rleSize;
            }
            chunk >>= 1;
            num0 = 0;
        }
        num0 = rem0;
    }
    assert(((rleSize + 7) / 8) == bv->rleSize);
    return DPS_OK;
}

#define TOP_UP_THRESHOLD 56

static DPS_Status RunLengthDecode(uint8_t* packed, size_t packedSize, chunk_t* bits)
{
    size_t bitPos = 0;
    uint64_t current;
    size_t currentBits = 0;

    memset(bits, 0, BITVEC_CONFIG_BYTE_LEN);

    if (packedSize) {
        currentBits = 8;
        current = *packed++;
        --packedSize;
    }
    while (currentBits) {
        /*
         * Keep the current bits above the threshold where we are guaranteed
         * contiguous bits to decode the lengths below.
         */
        while (packedSize && (currentBits <= TOP_UP_THRESHOLD)) {
            current |= (((uint64_t)*packed++) << currentBits);
            currentBits += 8;
            --packedSize;
        }
        if (!current) {
            assert(packedSize == 0);
            break;
        }
        if (current & 1) {
            current >>= 1;
            --currentBits;
        } else {
            uint64_t val;
            uint64_t num0;
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
            num0 = val + (((uint64_t)1 << tz) - 1);
            bitPos += num0;
            currentBits -= (1 + tz * 2);
            current >>= tz;
        }
        if (bitPos >= BITVEC_CONFIG_BIT_LEN) {
            return DPS_ERR_INVALID;
        }
        SET_BIT(bits, bitPos);
        ++bitPos;
    }
    return DPS_OK;
}

DPS_Status DPS_FHBitVectorSerialize(DPS_FHBitVector* bv, DPS_TxBuffer* buffer)
{
#ifdef ENDIAN_SWAP
#error(TODO bit vector endian swapping not implemented)
#else
    return CBOR_EncodeBytes(buffer, (const uint8_t*)bv->bits, FH_BITVECTOR_LEN);
#endif
}

static uint32_t RLESize(DPS_BitVector* bv)
{
    uint32_t i;
    uint32_t num0 = 0;
    chunk_t complement = 0;

    if (bv->rleSize) {
        return bv->rleSize;
    }
    /*
     * If the first pass doesn't compress by at least 50% try compressing the
     * complement and take the smaller of the two if compression is effective.
     */
    while (1) {
        uint32_t rleSize = 0;
        for (i = 0; i < NUM_CHUNKS; ++i) {
            uint32_t rem0;
            chunk_t chunk = bv->bits[i] ^ complement;
            if (!chunk) {
                num0 += CHUNK_SIZE;
                continue;
            }
            rem0 = CHUNK_SIZE;
            while (chunk) {
                uint32_t sz;
                int tz = COUNT_TZ(chunk);
                chunk >>= tz;
                rem0 -= tz + 1;
                num0 += tz;
                sz = Ceil_Log2(num0 + 1);
                rleSize += 1 + sz * 2;
                chunk >>= 1;
                num0 = 0;
            }
            num0 = rem0;
        }
        rleSize = (rleSize + 7) / 8;
        if (complement) {
            if (rleSize < bv->rleSize) {
                bv->rleSize = rleSize;
                bv->serializationFlags = FLAG_RLE_COMPLEMENT | FLAG_RLE_ENCODED;
            } else if (bv->rleSize >= BITVEC_CONFIG_BYTE_LEN) {
                bv->rleSize = BITVEC_CONFIG_BYTE_LEN;
                bv->serializationFlags = 0;
            }
            break;
        }
        if (rleSize < (BITVEC_CONFIG_BYTE_LEN / 2)) {
            bv->rleSize = rleSize;
            bv->serializationFlags = FLAG_RLE_ENCODED;
            break;
        }
        complement = ~0;
    }
    return bv->rleSize;
}

DPS_Status DPS_BitVectorSerialize(DPS_BitVector* bv, DPS_TxBuffer* buffer)
{
    DPS_Status ret;

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
    ret = CBOR_EncodeUint(buffer, bv->serializationFlags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeUint(buffer, BITVEC_CONFIG_BIT_LEN);
    if (ret != DPS_OK) {
        return ret;
    }
    if (bv->serializationFlags & FLAG_RLE_ENCODED) {
        ret = RunLengthEncode(bv, buffer);
    } else {
#ifdef ENDIAN_SWAP
#error(TODO bit vector endian swapping not implemented)
#else
        ret = CBOR_EncodeBytes(buffer, (const uint8_t*)bv->bits, BITVEC_CONFIG_BYTE_LEN);
#endif
    }
    return ret;
}

size_t DPS_FHBitVectorSerializedSize(DPS_FHBitVector* bv)
{
    return CBOR_SIZEOF_BYTES(FH_BITVECTOR_LEN);
}

DPS_Status DPS_FHBitVectorDeserialize(DPS_FHBitVector* bv, DPS_RxBuffer* buffer)
{
    uint8_t* data;
    size_t size;
    DPS_Status ret;

    ret = CBOR_DecodeBytes(buffer, &data, &size);
    if (ret == DPS_OK) {
        if (size == sizeof(bv->bits)) {
            memcpy(bv->bits, data, size);
        } else {
            DPS_ERRPRINT("Deserialized fuzzy hash bit vector has wrong length\n");
            ret = DPS_ERR_INVALID;
        }
    }
    return ret;
}

static void BitVectorComplement(DPS_BitVector* bv)
{
    size_t i;
    for (i = 0; i < NUM_CHUNKS; ++i) {
        bv->bits[i] = ~bv->bits[i];
    }
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
    if (len != BITVEC_CONFIG_BIT_LEN) {
        DPS_ERRPRINT("Deserialized bloom filter has wrong size\n");
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &data, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    bv->rleSize = (uint32_t)size;
    bv->serializationFlags = (uint8_t)flags;
    if (flags & FLAG_RLE_ENCODED) {
        ret = RunLengthDecode(data, size, bv->bits);
        if ((ret == DPS_OK) && (flags & FLAG_RLE_COMPLEMENT)) {
            BitVectorComplement(bv);
        }
    } else if (size == BITVEC_CONFIG_BYTE_LEN) {
        memcpy(bv->bits, data, size);
    } else {
        DPS_ERRPRINT("Deserialized bloom filter has wrong length\n");
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void DPS_BitVectorFill(DPS_BitVector* bv)
{
    if (bv) {
        memset(bv->bits, 0xFF, BITVEC_CONFIG_BYTE_LEN);
        bv->rleSize = BITVEC_CONFIG_BYTE_LEN;
    }
}

void DPS_BitVectorClear(DPS_BitVector* bv)
{
    memset(bv, 0, sizeof(DPS_BitVector));
}

size_t DPS_BitVectorSerializedSize(DPS_BitVector* bv)
{
    size_t rleLen = RLESize(bv);
    return CBOR_SIZEOF_ARRAY(3) +
        CBOR_SIZEOF_UINT(bv->serializationFlags) +
        CBOR_SIZEOF_UINT(BITVEC_CONFIG_BIT_LEN) +
        CBOR_SIZEOF_BYTES(rleLen);
}

void DPS_BitVectorDump(DPS_BitVector* bv, int dumpBits)
{
    if (DPS_DEBUG_ENABLED()) {
        DPS_PRINT("Pop = %u, ", DPS_BitVectorPopCount(bv));
        DPS_PRINT("RLE bytes = %u, ", RLESize(bv));
        DPS_PRINT("Loading = %.2f%%\n", (100.0 * DPS_BitVectorPopCount(bv) + 1.0) / BITVEC_CONFIG_BIT_LEN);
#ifdef DPS_DEBUG
        if (dumpBits) {
            CompressedBitDump(bv->bits, BITVEC_CONFIG_BIT_LEN);
        }
#endif
    }
}
