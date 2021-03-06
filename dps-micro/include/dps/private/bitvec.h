/**
 * @file
 * Bit vector and Bloom Filter operations
 */

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

#ifndef _BITVEC_H
#define _BITVEC_H

#include <stdint.h>
#include <stddef.h>
#include "io_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These are defined by the wire protocol
 */
#define BITVEC_CONFIG_BIT_LEN  8192
#define BITVEC_CONFIG_BYTE_LEN (BITVEC_CONFIG_BIT_LEN / 8)
#define BITVEC_CONFIG_HASHES     3

/**
 * Type for a bit vector
 */
typedef struct _DPS_BitVector {
    uint8_t serializationFlags;
    uint32_t rleSize;
    uint64_t bits[BITVEC_CONFIG_BIT_LEN / 64];
} DPS_BitVector;

/**
 * The fuzzy-hash is a fixed size bit vector
 */
typedef struct _DPS_FuzzyHash {
    uint64_t bits[4];
} DPS_FuzzyHash;

/**
 * Bloom Filter insertion operation.
 *
 * @param bv     An initialized bit vector
 * @param data   Data for the item to add
 * @param len    Length of the data to add
 */
void DPS_BitVectorBloomInsert(DPS_BitVector* bv, const uint8_t* data, size_t len);

/**
 * Bloom Filter existence check operation.
 *
 * @param bv    An initialized bit vector
 * @param data  Data for the item to check for
 * @param len   Length of the data to check
 *
 * @return 1 if the item is present, 0 if not.
 */
int DPS_BitVectorBloomTest(const DPS_BitVector* bv, const uint8_t* data, size_t len);

/**
 * Compute the load factor of the bit vector. The value returned is in
 * the range 0.0..100.0 and is the percentage of bits set in the bit
 * vector.
 *
 * @param bv   An initialized bit vector
 *
 * @return the load factor
 */
float DPS_BitVectorLoadFactor(DPS_BitVector* bv);

/**
 * Compute the population count (number of bits set) of the bit vector.
 *
 * @param bv   An initialized bit vector
 *
 * @return the population count
 */
uint32_t DPS_BitVectorPopCount(DPS_BitVector* bv);

/**
 * Generate a "fuzzy hash" (also called a "similarity preserving
 * hash") of a bit vector. The hash has the additional strong property
 * that given two bit vectors A and B where A is a superset of B,
 * FuzzyHash(A) will be a superset of FuzzyHash(B). The purpose of the fuzzy hash
 * is to encode some of information that is lost when a union is
 * formed from bit vectors from multiple subscriptions. For example the
 * fuzzy hash encodes the minimum number of bits that are needed to 
 * match any of the bit vectors that were combined by the union.
 *
 * To have the correct size the hash bit vector must has been
 * allocated by calling DPS_BitVectorAllocFH().
 *
 * @param hash  Returns the fuzzy hash of the input bit vector
 * @param bv    An initialized bit vector
 */
void DPS_BitVectorFuzzyHash(DPS_FuzzyHash* hash, DPS_BitVector* bv);

/**
 * Duplicate a FuzzyHash bit vector
 *
 * @param dst Destination bit vector
 * @param src Source bit vector
 */
static inline void DPS_FuzzyHashDup(DPS_FuzzyHash* dst, DPS_FuzzyHash* src)
{
    memcpy(dst, src, sizeof(DPS_FuzzyHash));
}

/**
 * Buffer space needed to serialize a FuzzyHash bit vector.
 *
 * @param bv  The FuzzyHash bit vector to serialize
 *
 * @return  The buffer space needed to serialize the bit vector.
 */
size_t DPS_FuzzyHashSerializedSize(DPS_FuzzyHash* bv);

/**
 * Serialize a FuzzyHash bit vector into a buffer
 *
 * @param bv      The FuzzyHash bit vector to serialize
 * @param buffer  The buffer to serialize the bit vector into
 *
 * @return  The success or failure of the operation
 */
DPS_Status DPS_FuzzyHashSerialize(DPS_FuzzyHash* bv, DPS_TxBuffer* buffer);

/**
 * Deserialize a FuzzyHash bit vector from a buffer
 *
 * @param bv      The FuzzyHash bit vector to deserialize
 * @param buffer  The buffer to deserialize the bit vector from
 *
 * @return  The success or failure of the operation
 */
DPS_Status DPS_FuzzyHashDeserialize(DPS_FuzzyHash* bv, DPS_RxBuffer* buffer);

/**
 * Check if one bit vector includes all bits of another. The two bit
 * vectors must be the same size.  Returns DPS_FALSE is bv1 has no
 * bits set.
 *
 * @param bv1   An initialized bit vector
 * @param bv2   The bit vector to test for inclusion
 *
 * @return
 * - DPS_TRUE  if the bv2 is included in bv1.
 * - DPS_FALSE if the bv2 is not included in bv1 or if the two bit
 *             vectors cannot be compared.
 */
int DPS_BitVectorIncludes(const DPS_BitVector* bv1, const DPS_BitVector* bv2);

/**
 * Check if two bit vectors are identical.
 *
 * @param bv1   An initialized bit vector
 * @param bv2   An initialized bit vector
 *
 * @return
 * - DPS_TRUE  if the two bit vectors are identical
 * - DPS_FALSE if the two bit vectors are different or if the two bit
 *             vectors cannot be compared.
 */
int DPS_BitVectorEquals(const DPS_BitVector* bv1, const DPS_BitVector* bv2);

/**
 * Returns the intersection of two fuzzy hash bit vectors.
 *
 * @param fhOut   The result of the intersection (can be same as fh1 or fh2)
 * @param fh1     A fuzzy hash bit vector
 * @param fh2     A fuzzy hash bit vector
 *
 * @return DPS_OK if computing the intersection is successful, an error
 *         otherwise
 */
DPS_Status DPS_FuzzyHashIntersection(DPS_FuzzyHash* fhOut, DPS_FuzzyHash* fh1, DPS_FuzzyHash* fh2);

/**
  * Set all the bits in a fuzzy hash bit vector
  *
  * @param fh  The bit vector to fill
  */
void DPS_FuzzyHashFill(DPS_FuzzyHash* fh);

/**
 * Forms the union of two bit vectors.
 *
 * @param bvOut  The bit vector to form a union with
 * @param bv     A bit vector
 *
 * @return DPS_OK if computing the union is successful, an error
 *         otherwise
 */
DPS_Status DPS_BitVectorUnion(DPS_BitVector* bvOut, DPS_BitVector* bv);

/**
 * Compress and serialize a bit vector into a buffer
 *
 * @param bv      The bit vector to serialize
 * @param buffer  The buffer to serialize the bit vector into
 *
 * @return  The success or failure of the operation
 */
DPS_Status DPS_BitVectorSerialize(DPS_BitVector* bv, DPS_TxBuffer* buffer);

/**
 * Buffer space needed to serialize a bit vector.
 *
 * @param bv  The bit vector to check
 *
 * @return  The buffer space needed to serialize a bit vector.
 */
size_t DPS_BitVectorSerializedSize(DPS_BitVector* bv);

/**
 * Deserialize an decompress a bit vector from a buffer
 *
 * @param bv      Allocated bit vector to deserialize into
 * @param buffer  The buffer containing a serialized bit vector
 *
 * @return  an initialized bit vector or null if the deserialization failed
 */
DPS_Status DPS_BitVectorDeserialize(DPS_BitVector* bv, DPS_RxBuffer* buffer);

/**
 * Clear all bits in an existing bit vector.
 *
 * @param bv  The bit vector to clear.
 */
void DPS_BitVectorClear(DPS_BitVector* bv);

/**
 * Test if bit vector has no bits set.
 *
 * @param bv  The bit vector to test.
 *
 * @return DPS_TRUE if the bit vector has no bits set, DPS_FALSE
 *         otherwise.
 */
int DPS_BitVectorIsClear(DPS_BitVector* bv);

/**
 * Duplicate a bit vector
 *
 * @param dst Destination bit vector
 * @param src Source bit vector
 */
void DPS_BitVectorDup(DPS_BitVector* dst, DPS_BitVector* src);

/**
 * Compute the xor of two bit vectors. The bit vectors must be the
 * same size.
 *
 * @param bvOut   The bit vector to receive the difference (can be same as bv1 or bv2)
 * @param bv1     A bit vector
 * @param bv2     A bit vector
 * @param equal   Returns non-zero if the two bit input vectors are identical in which case
 *                the output vector will be cleared. Can be NULL.
 *
 * @return DPS_OK if computing the xor is successful, an error
 *         otherwise
 */
DPS_Status DPS_BitVectorXor(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2, int* equal);

/**
 * Dump information about a bit vector
 *
 * @param bv    The bit vector to dump
 */
void DPS_BitVectorDump(DPS_BitVector* bv, int dumpBits);


#ifdef __cplusplus
}
#endif

#endif
