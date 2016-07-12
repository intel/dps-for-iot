#include <stdlib.h>
#include <bitvec.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <endian.h>
#include <dps_dbg.h>
#include <cbor.h>
#include <murmurhash3.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#if __BYTE_ORDER != __LITTLE_ENDIAN
#define ENDIAN_SWAP
#endif

#define BSWAP_32(n)  __builtin_bswap32(n)


#ifndef DPS_CONFIG_BIT_LEN
#define DPS_CONFIG_BIT_LEN 8192
#endif

#if DPS_CONFIG_BIT_LEN & 63
#error "Default DPS_CONFIG_BIT_LEN must be a multiple of 64"
#endif

#ifndef DPS_CONFIG_HASHES
#define DPS_CONFIG_HASHES 3
#endif

#if (DPS_CONFIG_HASHES < 1 || DPS_CONFIG_HASHES > 16)
#error "Default DPS_CONFIG_HASHES must be in range 1..16"
#endif

#ifndef DPS_CONFIG_SCALE_FACTOR
#define DPS_CONFIG_SCALE_FACTOR DPS_CONFIG_BIT_LEN / 256
#endif

#ifndef DPS_CONFIG_BIT_EXPANSION
#define DPS_CONFIG_BIT_EXPANSION 10
#endif

/*
 * Flag that indicates if serialized bit vector was rle encode or sent raw
 */
#define FLAG_RLE_ENCODED     0x80

/*
 * Indicates the complement of the bit vector was serialized
 */
#define FLAG_RLE_COMPLEMENT  0x40

/*
 * Process bit vector in 32 or 64 bit chunks
 */
#ifndef CHUNK_SIZE
#define CHUNK_SIZE 32
#endif

#if CHUNK_SIZE == 32

typedef uint32_t chunk_t;
#define SET_BIT(a, b)   (a)[(b) >> 5] |= (1 << ((b) & 0x1F))
#define TEST_BIT(a, b) ((a)[(b) >> 5] & (1 << ((b) & 0x1F)))
#define POPCOUNT(n)  __builtin_popcountl((chunk_t)n)
#define COUNT_TZ(n)  __builtin_ctzl((chunk_t)n)

#elif CHUNK_SIZE == 64

typedef uint64_t chunk_t;
#define SET_BIT(a, b)   (a)[(b) >> 6] |= (1 << ((b) & 0x3F))
#define TEST_BIT(a, b) ((a)[(b) >> 6] & (1 << ((b) & 0x3F)))
#define POPCOUNT(n)  __builtin_popcountll((chunk_t)n)
#define COUNT_TZ(n)  __builtin_ctzll((chunk_t)n)

#else
#error "CHUNK_SIZE must be 32 or 64 bits"
#endif

struct _DPS_BitVector {
    size_t len;
    chunk_t bits[1];
};

typedef struct {
    size_t bitLen;
    size_t numHashes;
    size_t scaleFactor;
    size_t bitExpansion;
} Configuration;

/*
 * Compile time defaults for the configuration parameters
 */
static Configuration config = { DPS_CONFIG_BIT_LEN, DPS_CONFIG_HASHES, DPS_CONFIG_SCALE_FACTOR, DPS_CONFIG_BIT_EXPANSION };

#define NUM_CHUNKS(bv)  ((bv)->len / CHUNK_SIZE)

#ifdef DPS_DEBUG
static void BitDump(const chunk_t* data, size_t bits)
{
    size_t i;
    for (i = 0; i < bits; ++i) {
        putc(TEST_BIT(data, i) ? '1' : '0', stderr);
        if ((i & 63) == 63) {
            putc('\n', stderr);
        }
    }
    putc('\n', stderr);
}
#endif

#define MIN_HASHES    1
#define MAX_HASHES   16

DPS_Status DPS_Configure(size_t bitLen, size_t numHashes, size_t scaleFactor, size_t bitExpansion)
{
    if (bitLen & 63) {
        DPS_ERRPRINT("Bit length must be a multiple of 64\n");
        return DPS_ERR_ARGS;
    }
    if (numHashes < MIN_HASHES || numHashes > MAX_HASHES) {
        DPS_ERRPRINT("Number of hashes must be in the range 1..16\n");
        return DPS_ERR_ARGS;
    }
    if ((bitLen % scaleFactor) || ((bitLen / scaleFactor) % 64)) {
        DPS_ERRPRINT("Bit length divided by scaleFactor must be a multiple of 64\n");
        return DPS_ERR_ARGS;
    }
    if (bitExpansion > 100) {
        DPS_ERRPRINT("Bit bitExpansion for densification must be a percentage (0..100)\n");
        return DPS_ERR_ARGS;
    }
    config.bitLen = bitLen;
    config.numHashes = numHashes;
    config.scaleFactor = scaleFactor;
    config.bitExpansion = bitExpansion;
    return DPS_ERR_OK;
}


static uint32_t Hash(const uint8_t* data, size_t len, uint8_t hashNum)
{
    uint32_t hash;
    /*
     * These are just random numbers
     */
    static const uint32_t Seeds[16] = {
        0x2dbcd6b2,
        0x7756c402,
        0x34bae8e3,
        0x8c86f563,
        0xc1312fdc,
        0xe4bd86ac,
        0xa2ed06f6,
        0x1ec69ce9,
        0x204de832,
        0xf206107b,
        0xc3fe6144,
        0x061f9cf5,
        0x20058da7,
        0x43c6b743,
        0x728afedd,
        0x21c32156
    };
    MurmurHash3_x86_32(data, len, Seeds[hashNum], &hash);
    return hash;
}


static DPS_BitVector* Alloc(size_t sz)
{
    DPS_BitVector* bv = NULL;

    if (sz % 64) {
        return NULL;
    }
    bv = malloc(sizeof(DPS_BitVector) - sizeof(chunk_t) + (sz / 8));
    if (bv) {
        bv->len = sz;
        DPS_BitVectorClear(bv);
    }
    return bv;
}

DPS_BitVector* DPS_BitVectorAlloc()
{
    return Alloc(config.bitLen);
}

int DPS_BitVectorIsClear(DPS_BitVector* bv)
{
    size_t i;
    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        if (bv->bits[i]) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

static size_t PopCount(const DPS_BitVector* bv)
{
    size_t popCount = 0;
    size_t i;
    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        popCount += POPCOUNT(bv->bits[i]);
    }
    return popCount;
}

DPS_BitVector* DPS_BitVectorClone(DPS_BitVector* bv)
{
    DPS_BitVector* clone = Alloc(bv->len);
    if (clone) {
        memcpy(clone->bits, bv->bits, bv->len / 8);
    }
    return clone;
}

void DPS_BitVectorFree(DPS_BitVector* bv)
{
    if (bv) {
        free(bv);
    }
}

void DPS_BitVectorBloomInsert(DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    size_t h;
    for (h = 0; h < config.numHashes; ++h) {
        uint32_t index = Hash(data, len, h) % bv->len;
        SET_BIT(bv->bits, index);
    }
}

int DPS_BitVectorBloomTest(const DPS_BitVector* bv, const uint8_t* data, size_t len)
{
    size_t h;
    for (h = 0; h < config.numHashes; ++h) {
        size_t index = Hash(data, len, h) % bv->len;
        if (!TEST_BIT(bv->bits, index)) {
            return 0;
        }
    }
    return 1;
}

float DPS_BitVectorLoadFactor(const DPS_BitVector* bv)
{
    return (100.0 * PopCount(bv) + 1.0) / bv->len;
}

int DPS_BitVectorEquals(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    if (bv1->len != bv2->len) {
        return 0;
    }
    if (memcmp(bv1->bits, bv2->bits, bv1->len / 8) == 0) {
        return 1;
    } else {
        return 0;
    }
}

int DPS_BitVectorIncludes(const DPS_BitVector* bv1, const DPS_BitVector* bv2)
{
    size_t i;
    const chunk_t* b1 = bv1->bits;
    const chunk_t* b2 = bv2->bits;

    if (!bv1 || !bv2) {
        return DPS_ERR_NULL;
    }
    for (i = 0; i < NUM_CHUNKS(bv1); ++i) {
        if ((bv1->bits[i] & bv2->bits[i]) != bv2->bits[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Reduce filter size by folding. 
 */
static DPS_BitVector* Scale(DPS_BitVector* bv)
{
    size_t len = bv->len / config.scaleFactor;
    size_t stride = NUM_CHUNKS(bv) / config.scaleFactor;
    DPS_BitVector* fold = Alloc(len);
    if (fold) {
        size_t f;
        for (f = 0; f < NUM_CHUNKS(fold); ++f) {
            size_t i;
            for (i = 0; i < NUM_CHUNKS(bv); i += stride) {
                fold->bits[f] |= bv->bits[i + f];
            }
        }
    }
    return fold;
}

/*
 * For unit testing only
 */
DPS_BitVector* DPS_BitVectorScale_Test(DPS_BitVector* bv, size_t scaleFactor)
{
    size_t r = config.scaleFactor;
    DPS_BitVector* scaled;
    config.scaleFactor = scaleFactor;
    scaled = Scale(bv);
    config.scaleFactor = r;
    return scaled;
}

/*
 * Very simple linear congruational generator based PRNG (Lehmer/Park-Miller generator) 
 */
#define LEPRNG(n)  (uint32_t)(((uint64_t)(n) * 279470273ull) % 4294967291ul)

/*
 * A randomly chosen 32 bit prime
 */
#define OFFSET 3973950899

static void DistributeBits(DPS_BitVector* bv, size_t expansion, size_t bit)
{
    size_t len = bv->len;
    uint32_t rnd = bit + OFFSET;
    while (expansion--) {
        rnd = LEPRNG(rnd);
        SET_BIT(bv->bits, rnd % len);
    }
}

DPS_BitVector* DPS_BitVectorWhiten(DPS_BitVector* bv)
{
    size_t i;
    size_t len = config.bitLen / config.scaleFactor;
    size_t expansion = len * config.bitExpansion / 100;
    DPS_BitVector* scaled;
    DPS_BitVector* whitened = Alloc(len);

    if (!whitened) {
        return NULL;
    }
    if (!bv) {
        return whitened;
    }
    assert(bv->len == config.bitLen);
    scaled = Scale(bv);
    if (!scaled) {
        DPS_BitVectorFree(whitened);
        return NULL;
    }
    for (i = 0; i < NUM_CHUNKS(scaled); ++i) {
        size_t bit = 0;
        chunk_t chunk = scaled->bits[i];
        while (chunk) {
            if (chunk & 1) {
                DistributeBits(whitened, expansion, bit);
            }
            chunk >>= 1;
            ++bit;
        }
    }
    DPS_BitVectorFree(scaled);
    return whitened;
}

DPS_Status DPS_BitVectorUnion(DPS_BitVector* bvOut, DPS_BitVector* bv)
{
    size_t i;
    if (!bvOut || !bv) {
        return DPS_ERR_NULL;
    }
    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        bvOut->bits[i] |= bv->bits[i];
    }
    return DPS_OK;
}

DPS_Status DPS_BitVectorIntersection(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2)
{
    size_t i;
    if (!bvOut || !bv1 || !bv2) {
        return DPS_ERR_NULL; 
    }
    for (i = 0; i < NUM_CHUNKS(bv1); ++i) {
        bvOut->bits[i] = bv1->bits[i] & bv2->bits[i];
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


static DPS_Status RunLengthEncode(const DPS_BitVector* bv, DPS_Buffer* buffer, size_t* size, uint8_t flags)
{
    size_t i;
    size_t rleSize = 0;
    size_t sz;
    uint32_t num0 = 0;
    uint8_t* packed = buffer->pos;
    size_t maxEncode = DPS_BufferSpace(buffer) * 8;
    chunk_t complement = flags & FLAG_RLE_COMPLEMENT ? ~0 : 0;

    /*
     * We only need to set the 1's
     */
    memset(packed, 0, DPS_BufferSpace(buffer));

    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        size_t rem0;
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
            if ((rleSize + sz) > maxEncode) {
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
    if (rleSize > bv->len) {
        return DPS_ERR_OVERFLOW;
    }
    *size = (rleSize + 7) / 8;
    buffer->pos += *size;
    return DPS_OK;
}

#define TOP_UP_THRESHOLD 56

static DPS_Status RunLengthDecode(uint8_t* packed, size_t packedSize, chunk_t* bits, size_t len)
{
    size_t bitPos = 0;
    uint64_t current;
    size_t currentBits = 0;

    memset(bits, 0, len / 8);

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
            uint32_t val;
            int num0;
            int tz = COUNT_TZ(current);

            current >>= (tz + 1);
            /*
             * We can extract the length with a mask
             */
            val = current & ((1 << tz) - 1);
            /*
             * The value is little-endia so we May need to do an endian swap
             */
#ifdef ENDIAN_SWAP
            val = BSWAP_32(val);
#endif
            num0 = val + ((1 << tz) - 1);
            bitPos += num0;
            if (bitPos >= len) {
                break;
            }
            currentBits -= (1 + tz * 2);
            current >>= tz;
        }
        SET_BIT(bits, bitPos);
        ++bitPos;
    }
    if (bitPos > len) {
        return DPS_ERR_INVALID;
    }
    return DPS_OK;
}

DPS_Status DPS_BitVectorSerialize(const DPS_BitVector* bv, DPS_Buffer* buffer)
{
    DPS_Status ret;
    uint8_t flags;
    float load = DPS_BitVectorLoadFactor(bv);

    /*
     * The load factor will tell us if it is worth trying run length encoding and if
     * the bit complement will result in a more compact encoding.
     */
    if (load < 30.0) {
        flags = FLAG_RLE_ENCODED;
    } else if (load > 70.0) {
        flags = FLAG_RLE_ENCODED | FLAG_RLE_COMPLEMENT;
    } else{
        flags = 0;
    }
    while (1) {
        uint8_t* resetPos = buffer->pos;
        ret = CBOR_EncodeUint(buffer, flags);
        if (ret != DPS_OK) {
            return ret;
        }
        ret = CBOR_EncodeUint(buffer, bv->len);
        if (ret != DPS_OK) {
            return ret;
        }
        if (flags & FLAG_RLE_ENCODED) {
            size_t rleSize;
            size_t maxSize = DPS_BufferSpace(buffer) - 4;
            /*
             * Reserve space in the buffer
             */
            ret = CBOR_EncodeBytes(buffer, NULL, maxSize);
            if (ret == DPS_OK) {
                ret = RunLengthEncode(bv, buffer, &rleSize, flags);
                if (ret == DPS_OK) {
                    ret = CBOR_FixupLength(buffer, maxSize, rleSize);
                }
            } else if (ret == DPS_ERR_OVERFLOW) {
                /*
                 * Reset buffer and use raw encoding
                 */
                flags = 0;
                buffer->pos = resetPos;
                continue;
            }
        } else {
#ifdef ENDIAN_SWAP
#error(TODO bit vector endian swapping not implemented)
#else
            ret = CBOR_EncodeBytes(buffer, (const uint8_t*)bv->bits, bv->len / 8);
#endif
        }
        break;
    }
    return ret;
}

size_t DPS_BitVectorSerializeMaxSize(const DPS_BitVector* bv)
{
    return 8 + bv->len / 8;
}

DPS_Status DPS_BitVectorDeserialize(DPS_BitVector* bv, DPS_Buffer* buffer)
{
    DPS_Status ret;
    uint64_t flags;
    uint64_t len;
    uint8_t* data;

    ret = CBOR_DecodeUint(buffer, &flags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeUint(buffer, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (len != bv->len) {
        DPS_ERRPRINT("Deserialized bloom filter has wrong size\n");
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &data, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (flags & FLAG_RLE_ENCODED) {
        ret = RunLengthDecode(data, len, bv->bits, bv->len);
        if ((ret == DPS_OK) && (flags & FLAG_RLE_COMPLEMENT)) {
            DPS_BitVectorComplement(bv);
        }
    } else if (len == bv->len / 8) {
        memcpy(bv->bits, data, len);
    } else {
        DPS_ERRPRINT("Deserialized bloom filter has wrong length\n");
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void DPS_BitVectorFill(DPS_BitVector* bv)
{
    if (bv) {
        memset(bv->bits, 0xFF, bv->len / 8);
    }
}

void DPS_BitVectorClear(DPS_BitVector* bv)
{
    if (bv) {
        memset(bv->bits, 0, bv->len / 8);
    }
}

void DPS_BitVectorComplement(DPS_BitVector* bv)
{
    size_t i;
    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        bv->bits[i] = ~bv->bits[i];
    }
}

static size_t RLE_Size(const DPS_BitVector* bv)
{
    size_t i;
    size_t rleSize = 0;
    uint32_t num0 = 0;
    chunk_t complement = 0;
    float load = DPS_BitVectorLoadFactor(bv);

    if (load >= 30.0 && load <= 70.0) {
        return bv->len;
    }

    if (load > 70.0) {
        complement = ~complement;
    }

    for (i = 0; i < NUM_CHUNKS(bv); ++i) {
        size_t rem0;
        chunk_t chunk = bv->bits[i] ^ complement;
        if (!chunk) {
            num0 += CHUNK_SIZE;
            continue;
        }
        rem0 = CHUNK_SIZE;
        while (chunk) {
            size_t sz;
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
    return rleSize;
}

DPS_Status DPS_BitVectorSet(DPS_BitVector* bv, uint8_t* data, size_t len)
{
    if (len != (bv->len / 8)) {
        return DPS_ERR_ARGS;
    } else {
        memcpy(bv->bits, data, len);
        return DPS_OK;
    }
}

void DPS_BitVectorDump(const DPS_BitVector* bv, int dumpBits)
{
    if (DPS_DEBUG_ENABLED()) {
        DPS_PRINT("Bit len = %d, ", bv->len);
        DPS_PRINT("Pop = %d, ", PopCount((DPS_BitVector*)bv));
        DPS_PRINT("RLE bits = %d, ", RLE_Size(bv));
        DPS_PRINT("Loading = %.2f%%\n", DPS_BitVectorLoadFactor((DPS_BitVector*)bv));
#ifdef DPS_DEBUG
        if (dumpBits) {
            BitDump(bv->bits, bv->len);
        }
#endif
    }
}
