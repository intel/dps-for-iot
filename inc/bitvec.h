#ifndef _BLOOM_H
#define _BLOOM_H

#include <stdint.h>
#include <stddef.h>
#include <dps.h>

typedef struct _DPS_BitVector DPS_BitVector;

/**
 * Global configuration for this module. Overrides the default value for various global parameters. These are system
 * wide parameters that must be the same for all nodes participating in a single DPS network.
 *
 * @param  bitLen        The size of the bit vectors in bits.  The size must be a multiple of 64.
 * @param  numHashes     The number of hashes for Bloom filter operations - must be in the range 1..16.
 * @param  scaleFactor   The scaling down factor to use when doing whitening.
 * @param  bitExpansion  Expressed as a percentage, the entropy expansion when doing whitening
 *
 * @return   DPS_OK if the parameters are ok.
 *           DPS_ERR_ARGS if the setting values are not permitted.
 */
DPS_Status DPS_Configure(size_t bitLen, size_t numHashes, size_t scaleFactor, size_t bitExpansion);

/**
 * Bloom Filter insertion operation.
 *
 * @param bv        An intialized bit vector
 * @param data      Data for the item to add
 * @param len       Length of the data to add
 */
void DPS_BitVectorBloomInsert(DPS_BitVector* bv, const uint8_t* data, size_t len);

/**
 * Bloom Filter existence check operation.
 *
 * @param bv    An intialized bit vector
 * @param data  Data for the item to check for
 * @param len   Length of the data to check
 *
 * @return 1 if the item is present, 0 if not.
 */
int DPS_BitVectorBloomTest(const DPS_BitVector* bv, const uint8_t* data, size_t len);

/**
 * Allocates a bit vector using the default values set by DPS_Configure()
 *
 * @return  An initialized bloome filter or NULL if the allocation failed.
 */
DPS_BitVector* DPS_BitVectorAlloc();

/**
 * Clone a bit vector
 *
 * @param bv An intialized bit vector
 *
 * @return  An initialized context structure or NULL if the allocation failed.
 */
DPS_BitVector* DPS_BitVectorClone(DPS_BitVector* bv);

/**
 * Free resources for a bit vector
 *
 * @param bv   An intialized bit vector
 */
void DPS_BitVectorFree(DPS_BitVector* bv);

/**
 * Whiten the bit vector vector through a combination of scaling and entropy expansion that sets multiple bits (pseudo
 * randomly) for each bit set in the resultant bit vector.  If the input parameter is NULL the output is a cleared bit
 * vector of the correct scaled size.
 *
 * @param bv     An intialized bit vector or NULL
 *
 * @param   A whitened bit vector
 */
DPS_BitVector* DPS_BitVectorWhiten(DPS_BitVector* bv);

/**
 * Returns the load factor of the bit vector. The value returned is in the range 0.0..100.0 and is the percentage of
 * bits set in the filter
 *
 * @param bv   An intialized bit vector
 */
float DPS_BitVectorLoadFactor(const DPS_BitVector* bv);

/**
 * Check if one bit vector includes all bit of another. The two bit vectors must be the same size.
 *
 * @param bv1   An initialized bit vector
 * @param bv2   The bit vector to test for inclusion
 *
 * @return  - 1  if the bv2 is included in bv1.
 *          - 0  if the bv2 is not included in bv1.
 *          - -1 if the two bit vectors cannot be compared.
 */
int DPS_BitVectorIncludes(const DPS_BitVector* bv1, const DPS_BitVector* bv2);

/**
 * Check if two bit vectors are identical.
 *
 * @param bv1   An initialized bit vector
 * @param bv2   An initialized bit vector
 *
 * @return  - 1  if the two bit vectors are identical
 *          - 0  if the two bit vectors are different
 *          - -1 if the two bit vectors cannot be compared.
 */
int DPS_BitVectorEquals(const DPS_BitVector* bv1, const DPS_BitVector* bv2);

/**
 * Returns the intersection of two bit vectors. The bit vectors must be the same size.
 *
 * @param bvOut   The filter to form an intersection with (can be same as bv1 or bv2)
 * @param bv1     A bit vector
 * @param bv2     A bit vector
 */
DPS_Status DPS_BitVectorIntersection(DPS_BitVector* bvOut, DPS_BitVector* bv1, DPS_BitVector* bv2);

/**
 * Forms the union of two bit vectors.
 *
 * @param bvOut  The filter to form a union with
 * @param bv     A bit vector
 */
DPS_Status DPS_BitVectorUnion(DPS_BitVector* bvOut, DPS_BitVector* bv);

/**
 * Compress and serialize a bit vector into a buffer
 *
 * @param bv  The filter to serialize
 * @param buffer  The buffer to serialize the filter into
 *
 * @return  The success or failure of the operation
 */
DPS_Status DPS_BitVectorSerialize(const DPS_BitVector* bv, DPS_Buffer* buffer);

/**
 * Maximum buffer space needed to serialize a filter.
 *
 * @param bv  The filter to check
 *
 * @return  The maximum space needed to serialize a bit vector.
 */
size_t DPS_BitVectorSerializeMaxSize(const DPS_BitVector* bv);

/**
 * Deserialize an decompress a bit vector from a buffer
 *
 * @param bv      Allocated bit vector to deserialize into
 * @param buffer  The buffer containing a serialized bit vector
 *
 * @return  an initialized bit vector or null if the deserialization failed
 */
DPS_Status DPS_BitVectorDeserialize(DPS_BitVector* bv, DPS_Buffer* buffer);

/**
 * Clear all bits in an existing bit vector. 
 *
 * @param bv  The filter to clear.
 */
void DPS_BitVectorClear(DPS_BitVector* bv);

/**
 * Set all bits in an existing bit vector. 
 *
 * @param bv  The filter to set.
 */
void DPS_BitVectorFill(DPS_BitVector* bv);

/**
 * Returns 1 if the bit vector has no bits set, otherwise returns 0.
 *
 * @param bv  The filter to test.
 */
int DPS_BitVectorIsClear(DPS_BitVector* bv);

/**
 * Bitwise complement changes all 1's to 0's and 0's to 1's
 *
 * @param bv  The bit vector to complement.
 */
void DPS_BitVectorComplement(DPS_BitVector* bv);

/**
 * Set the bits in a bit vector. This is primarily for unit testing.
 *
 * @param bv      The filter to set
 * @param data    The data to set in the filter
 * @param len     The length of the data to set. This must match the bit size of the filter.
 */
DPS_Status DPS_BitVectorSet(DPS_BitVector* bv, uint8_t* data, size_t len);

/**
 * Dump information about a bit vector
 *
 * @param bv    The filter to dump
 * @param bits  If non-zero dump out the bit array
 */
void DPS_BitVectorDump(const DPS_BitVector* bv, int bits);

#endif
