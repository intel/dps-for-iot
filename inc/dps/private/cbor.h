/**
 * @file
 * CBOR encoding and decoding
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

#ifndef _CBOR_H
#define _CBOR_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum length for a string excluding NUL terminator
 */
#define CBOR_MAX_STRING_LEN 2048

/*
 * CBOR major types
 */
#define CBOR_UINT   (0 << 5) /**< CBOR major type unsigned integer */
#define CBOR_NEG    (1 << 5) /**< CBOR major type negative integer */
#define CBOR_BYTES  (2 << 5) /**< CBOR major type byte string */
#define CBOR_STRING (3 << 5) /**< CBOR major type text string */
#define CBOR_ARRAY  (4 << 5) /**< CBOR major type array of data items */
#define CBOR_MAP    (5 << 5) /**< CBOR major type map of pairs of data items */
#define CBOR_TAG    (6 << 5) /**< CBOR major type semantic tag */
/**
 * CBOR major type floating-point numbers and simple data types that
 * need no content, as well as the "break" stop code
 */
#define CBOR_OTHER  (7 << 5)

/**
 * CBOR "OTHER" flags
 */
#define CBOR_FALSE  (CBOR_OTHER | 20)   /**< CBOR option flag for boolean FALSE */
#define CBOR_TRUE   (CBOR_OTHER | 21)   /**< CBOR option flag for boolean TRUE */
#define CBOR_NULL   (CBOR_OTHER | 22)   /**< CBOR option flag for NULL value */
#define CBOR_FLOAT  (CBOR_OTHER | 26)   /**< CBOR option flag for 32 bit float */
#define CBOR_DOUBLE (CBOR_OTHER | 27)   /**< CBOR option flag for 64 bit float */

/**
 * Maximum bytes needed to encode any length
 */
#define CBOR_MAX_LENGTH (1 + sizeof(uint64_t))

/**
 * Actual bytes needed to encode a specific length
 */
#define CBOR_SIZEOF_LEN(l)      ((((l) < 24) ? 1 : (((l) <= UINT8_MAX) ? 2 : (((l) <= UINT16_MAX) ? 3 : ((((l) <= UINT32_MAX) ? 5 : 9))))))

/**
 * Actual bytes needed for encoding a map size
 */
#define CBOR_SIZEOF_MAP(m)       CBOR_SIZEOF_LEN(m)

/**
 * Actual bytes needed for encoding an array size
 */
#define CBOR_SIZEOF_ARRAY(a)     CBOR_SIZEOF_LEN(a)

/**
 * Actual bytes need to encode a string
 */
#define CBOR_SIZEOF_STRING(s)    _CBOR_SizeOfString(s)

/**
 * Actual bytes need to encode a static string (e.g. static const char str[])
 */
#define CBOR_SIZEOF_STATIC_STRING(s)    ((sizeof(s) - 1) + CBOR_SIZEOF_LEN(sizeof(s) - 1))

/**
 * Actual bytes need to encode a string of length bytes
 */
#define CBOR_SIZEOF_STRING_AND_LENGTH(l)    ((l) + CBOR_SIZEOF_LEN(l))

/**
 * Actual bytes needed to encode a byte stream of a specified length
 */
#define CBOR_SIZEOF_BYTES(l)     ((l) + CBOR_SIZEOF_LEN(l))

/**
 * Maximum bytes needed to encode an integer type
 */
#define CBOR_SIZEOF(t)          (1 + sizeof(t))

/**
 * Actual bytes need to encode a boolean
 */
#define CBOR_SIZEOF_BOOLEAN()    (1)

/**
 * Actual bytes need to encode an unsigned integer
 */
#define CBOR_SIZEOF_UINT(n)      CBOR_SIZEOF_LEN(n)

/**
 * Actual bytes need to encode a signed integer
 */
#define CBOR_SIZEOF_INT(i)       _CBOR_SizeOfInt(i)

/**
 * Actual bytes need to encode a tag
 */
#define CBOR_SIZEOF_TAG(n)       CBOR_SIZEOF_LEN(n)

/**
 * Actual bytes need to encode a null
 */
#define CBOR_SIZEOF_NULL()       (1)

/**
 * Actual bytes need to encode a float
 */
#define CBOR_SIZEOF_FLOAT()      (5)

/**
 * Actual bytes need to encode a double
 */
#define CBOR_SIZEOF_DOUBLE()     (9)

/**
 * Actual bytes need to encode a signed integer
 *
 * @param i The signed integer
 *
 * @return The number of bytes needed
 */
size_t _CBOR_SizeOfInt(int64_t i);

/**
 * Actual bytes need to encode a string
 *
 * @param s The string to encode
 *
 * @return The number of bytes needed
 */
size_t _CBOR_SizeOfString(const char* s);

/**
 * Encode a major type and the length of its value
 *
 * @param buffer   Buffer to append to
 * @param len      The length
 * @param maj      The major type
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeLength(DPS_TxBuffer* buffer, uint64_t len, uint8_t maj);

/**
 * Copy the supplied bytes to the encoded buffer
 *
 * @param buffer   Buffer to append to
 * @param data     The bytes to append
 * @param len      The number of bytes to append
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_Copy(DPS_TxBuffer* buffer, const uint8_t* data, size_t len);

/**
 * Encode an unsigned integer
 *
 * @param buffer   Buffer to append to
 * @param n        The unsigned integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeUint(DPS_TxBuffer* buffer, uint64_t n);

/**
 * Encode a signed integer
 *
 * @param buffer   Buffer to append to
 * @param i        The signed integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeInt(DPS_TxBuffer* buffer, int64_t i);

/**
 * Encode a byte string
 *
 * @param buffer   Buffer to append to
 * @param data     The byte string to append
 * @param len      The number of bytes to append
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeBytes(DPS_TxBuffer* buffer, const uint8_t* data, size_t len);

/**
 * Encode a text string
 *
 * @param buffer   Buffer to append to
 * @param str      The text string to append
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeString(DPS_TxBuffer* buffer, const char* str);

/**
 * Encode @p len bytes of a text string
 *
 * @param buffer   Buffer to append to
 * @param str      The text string to append
 * @param len      The number of characters to append
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeStringAndLength(DPS_TxBuffer* buffer, const char* str, size_t len);

/**
 * Encode an array type and the number of data items
 *
 * @param buffer   Buffer to append to
 * @param len      The number of data items
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeArray(DPS_TxBuffer* buffer, size_t len);

/**
 * Encode a map type and the number of pairs of data items
 *
 * @param buffer   Buffer to append to
 * @param len      The number of pairs of data items
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeMap(DPS_TxBuffer* buffer, size_t len);

/**
 * Encode a semantic tag
 *
 * @param buffer   Buffer to append to
 * @param n        The tag
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeTag(DPS_TxBuffer* buffer, uint64_t n);

/**
 * Encode a boolean
 *
 * @param buffer   Buffer to append to
 * @param b        The boolean value
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeBoolean(DPS_TxBuffer* buffer, int b);

/**
 * Encode a null
 *
 * @param buffer   Buffer to append to
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeNull(DPS_TxBuffer* buffer);

/**
 * Decode an unsigned 8-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param n        The unsigned integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeUint8(DPS_RxBuffer* buffer, uint8_t* n);

/**
 * Decode an unsigned 16-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param n        The unsigned integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeUint16(DPS_RxBuffer* buffer, uint16_t* n);

/**
 * Decode an unsigned 32-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param n        The unsigned integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeUint32(DPS_RxBuffer* buffer, uint32_t* n);

/**
 * Decode an unsigned integer
 *
 * @param buffer   Buffer to decode from
 * @param n        The unsigned integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeUint(DPS_RxBuffer* buffer, uint64_t* n);

/**
 * Decode a signed integer
 *
 * @param buffer   Buffer to decode from
 * @param i        The signed integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeInt(DPS_RxBuffer* buffer, int64_t* i);

/**
 * Decode a signed 8-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param i        The signed integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeInt8(DPS_RxBuffer* buffer, int8_t* i);

/**
 * Decode a signed 16-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param i        The signed integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeInt16(DPS_RxBuffer* buffer, int16_t* i);

/**
 * Decode a signed 32-bit integer
 *
 * @param buffer   Buffer to decode from
 * @param i        The signed integer
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeInt32(DPS_RxBuffer* buffer, int32_t* i);

/**
 * Decode a map
 *
 * @param buffer   Buffer to decode from
 * @param size     The number of pairs of data items
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeMap(DPS_RxBuffer* buffer, size_t* size);

/**
 * Decode a semantic tag
 *
 * @param buffer   Buffer to decode from
 * @param n        The semantic tag
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeTag(DPS_RxBuffer* buffer, uint64_t* n);

/**
 * Decode a boolean
 *
 * @param buffer   Buffer to decode from
 * @param b        The boolean value
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeBoolean(DPS_RxBuffer* buffer, int* b);

/**
 * Reserve bytes in the encoded buffer for encoding a byte string.
 *
 * Write the length, adjust the buffer pointer and return the
 * pointer to the start of where the bytes are to be written.
 *
 * @param buffer   Buffer to append to
 * @param len      The length of the byte string
 * @param ptr      The start of where the bytes are to be written
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_ReserveBytes(DPS_TxBuffer* buffer, size_t len, uint8_t** ptr);

/**
 * Prepare a CBOR structure to be wrapped in a bytes stream. This function
 * is used when the exact length of data to be enclosed is not know ahead
 * of time.
 *
 * @param buffer   The buffer to encode into
 * @param hintLen  Estimated size of the bytes to be wrapped
 * @param wrapPtr  Returns pointer to start of the byte stream
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_StartWrapBytes(DPS_TxBuffer* buffer, size_t hintLen, uint8_t** wrapPtr);

/**
 * Finalize byte stream wrapping of a CBOR encode structure by fixing
 * up the actual length and if necessary moving the data
 *
 * @param buffer   The buffer to encode into
 * @param wrapPtr  The pointer that was returned by CBOR_StartWrapBytes
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EndWrapBytes(DPS_TxBuffer* buffer, uint8_t* wrapPtr);

/**
 * For symmetry with CBOR_DecodeInt8()
 */
#define CBOR_EncodeInt8(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/**
 * For symmetry with CBOR_DecodeInt16()
 */
#define CBOR_EncodeInt16(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/**
 * For symmetry with CBOR_DecodeInt32()
 */
#define CBOR_EncodeInt32(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/**
 * For symmetry with CBOR_DecodeUint8()
 */
#define CBOR_EncodeUint8(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/**
 * For symmetry with CBOR_DecodeUint16()
 */
#define CBOR_EncodeUint16(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/**
 * For symmetry with CBOR_DecodeUint32()
 */
#define CBOR_EncodeUint32(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/**
 * Encode a float
 *
 * @param buffer   Buffer to append to
 * @param f        The float
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeFloat(DPS_TxBuffer* buffer, float f);

/**
 * Encode a double
 *
 * @param buffer   Buffer to append to
 * @param d        The double
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_EncodeDouble(DPS_TxBuffer* buffer, double d);

/**
 * Decode a byte string
 *
 * @param buffer  Buffer to decode from
 * @param data    Returns pointer into buffer storage to the decoded bytes
 * @param size    Returns length of the decoded bytes
 *
 * @return
 * - DPS_OK if the bytes were decoded
 * - DPS_ERR_INVALID if the major is not byte string
 * - DPS_ERR_EOD if there was insufficient data in the buffer
 */
DPS_Status CBOR_DecodeBytes(DPS_RxBuffer* buffer, uint8_t** data, size_t* size);

/**
 * Decode a text string
 *
 * @note This function excludes the trailing NUL in the returned length.
 *
 * @param buffer  Buffer to decode from
 * @param data    Returns pointer into buffer storage to the decoded string
 * @param size    Returns length of the decoded string
 *
 * @return
 * - DPS_OK if the string was decoded
 * - DPS_ERR_INVALID if the major is not string
 * - DPS_ERR_EOD if there was insufficient data in the buffer
 */
DPS_Status CBOR_DecodeString(DPS_RxBuffer* buffer, char** data, size_t* size);

/**
 * Decode an array
 *
 * @param buffer  Buffer to decode from
 * @param size    Returns number of array items
 *
 * @return
 * - DPS_OK if the array was decoded
 * - DPS_ERR_INVALID if the major is not an array
 * - DPS_ERR_EOD if there was insufficient data in the buffer
 */
DPS_Status CBOR_DecodeArray(DPS_RxBuffer* buffer, size_t* size);

/**
 * Decode a float
 *
 * @param buffer   Buffer to append to
 * @param f        The float
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeFloat(DPS_RxBuffer* buffer, float* f);

/**
 * Decode a double
 *
 * @param buffer   Buffer to append to
 * @param d        The double
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status CBOR_DecodeDouble(DPS_RxBuffer* buffer, double* d);

/**
 * Skip a CBOR value
 *
 * @param buffer  Buffer to decode from
 * @param maj     Returns the major type of the value skipped
 * @param skipped Returns number of bytes skipped
 *
 * @return
 * - DPS_OK if the buffer was decoded
 * - DPS_ERR_EOD if there was insufficient data in the buffer
 */
DPS_Status CBOR_Skip(DPS_RxBuffer* buffer, uint8_t* maj, size_t* skipped);

/**
 * Peek at the next value in the encoded buffer
 *
 * @param buffer  Buffer to decode from
 * @param maj     Returns the major type of the next value
 * @param info    Returns the additional information of the next value
 *
 * @return
 * - DPS_OK if the buffer was decoded
 * - DPS_ERR_EOD if there was insufficient data in the buffer
 */
DPS_Status CBOR_Peek(DPS_RxBuffer* buffer, uint8_t* maj, uint64_t* info);

/**
 * Structure for holding state while parsing a map
 */
typedef struct {
    DPS_RxBuffer* buffer; /**< Receive buffer being parsed */
    const int32_t* needs; /**< Array of remaining mandatory keys to match */
    size_t needKeys;      /**< Remaining number of unmatched mandatory keys */
    const int32_t* wants; /**< Array of remaining optional keys to match */
    size_t wantKeys;      /**< Remaining number of unmatched optional keys */
    size_t entries;       /**< Remaining entries in map */
    DPS_Status result;    /**< Result of parsing effort */
} CBOR_MapState;

/**
 * Helper function for matching keys in a map. The keys must be signed integers and
 * fit in 32 bits. The keys must be in ascending order in the keys array and in the
 * map being parsed.
 *
 * @param mapState   Map state struct to initialize
 * @param buffer     Buffer to parse from
 * @param keys       Array of mandatory keys to be matched
 * @param numKeys    The number of mandatory keys to match
 * @param optKeys    Array of optional keys to be matched
 * @param numOptKeys The number of optional keys to match
 *
 * @return DPS_OK if parsing the map is successful, an error otherwise
 */
DPS_Status DPS_ParseMapInit(CBOR_MapState* mapState, DPS_RxBuffer* buffer, const int32_t* keys,
                            size_t numKeys, const int32_t* optKeys, size_t numOptKeys);

/**
 * Find the next matching key and return it. The value for the key can be
 * decoded from the buffer.
 *
 * @param mapState  Map state struct
 * @param key       Returns the key that was matched
 *
 * @return
 * - DPS_OK if the required key was matched
 * - DPS_ERR_MISSING if a required key was not found
 * - other errors if the CBOR was invalid
 */
DPS_Status DPS_ParseMapNext(CBOR_MapState* mapState, int32_t* key);

/**
 * Check that a map has been completely parsed
 *
 * @param mapState  Map state struct
 *
 * @return DPS_TRUE if done, DPS_FALSE otherwise
 */
int DPS_ParseMapDone(CBOR_MapState* mapState);

#ifdef DPS_DEBUG
/**
 * Print an encoded CBOR value
 *
 * @param tag   Optional tag of the value
 * @param data  The encoded value
 * @param len   The number of bytes of the encoded value
 */
void CBOR_Dump(const char* tag, uint8_t* data, size_t len);
#else
#define CBOR_Dump(t, d, l)
#endif

#ifdef __cplusplus
}
#endif

#endif
