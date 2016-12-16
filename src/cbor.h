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

/*
 * CBOR major types
 */
#define CBOR_UINT   (0 << 5)
#define CBOR_NEG    (1 << 5)
#define CBOR_BYTES  (2 << 5)
#define CBOR_STRING (3 << 5)
#define CBOR_ARRAY  (4 << 5)
#define CBOR_MAP    (5 << 5)
#define CBOR_TAG    (6 << 5)
#define CBOR_OTHER  (7 << 5)

/*
 * Maximum bytes needed to encode any length
 */
#define CBOR_MAX_LENGTH (1 + sizeof(uint64_t))

/*
 * Actual bytes needed to encode a specific length (up to (2^16 - 1))
 */
#define CBOR_SIZEOF_LEN(l)      ((((l) < 24) ? 1 : (((l) < 256) ? 2 : 3)))

/*
 * Actual bytes needed for encoding a map size
 */
#define CBOR_SIZEOF_MAP(m)       CBOR_SIZEOF_LEN(m)

/*
 * Actual bytes needed for encoding an array size
 */
#define CBOR_SIZEOF_ARRAY(a)     CBOR_SIZEOF_LEN(a)

/*
 * Actual bytes need to encode a string (includes NUL terminator)
 */
#define CBOR_SIZEOF_STRING(s)    _CBOR_SizeOfString(s)

/*
 * Actual bytes needed to encode a byte stream of a specified length
 */
#define CBOR_SIZEOF_BSTR(l)     ((l) + CBOR_SIZEOF_LEN(l))

/*
 * Maximum bytes needed to encode an integer type
 */
#define CBOR_SIZEOF(t)          (1 + sizeof(t))

/*
 * Actual bytes need to encode a boolean
 */
#define CBOR_SIZEOF_BOOL        (1)

size_t _CBOR_SizeOfString(const char* s);

DPS_Status CBOR_EncodeLength(DPS_Buffer* buffer, uint64_t len, uint8_t maj);

DPS_Status CBOR_Copy(DPS_Buffer* buffer, const uint8_t* data, size_t len);

DPS_Status CBOR_EncodeUint(DPS_Buffer* buffer, uint64_t n);

DPS_Status CBOR_EncodeInt(DPS_Buffer* buffer, int64_t i);

DPS_Status CBOR_EncodeBytes(DPS_Buffer* buffer, const uint8_t* data, size_t len);

/*
 * Note - this function automatically appends the trailing NUL. To encode a string
 * without the trailing NUL use
 *
 *  CBOR_EncodeLength(buf, strlen(str), CBOR_STRING);
 *  CBOR_Copy(buf, str, strlen(str));
 */
DPS_Status CBOR_EncodeString(DPS_Buffer* buffer, const char* str);

DPS_Status CBOR_EncodeArray(DPS_Buffer* buffer, size_t len);

DPS_Status CBOR_EncodeMap(DPS_Buffer* buffer, size_t len);

DPS_Status CBOR_EncodeTag(DPS_Buffer* buffer, uint64_t n);

DPS_Status CBOR_EncodeBoolean(DPS_Buffer* buffer, int b);

DPS_Status CBOR_DecodeUint8(DPS_Buffer* buffer, uint8_t* n);

DPS_Status CBOR_DecodeUint16(DPS_Buffer* buffer, uint16_t* n);

DPS_Status CBOR_DecodeUint32(DPS_Buffer* buffer, uint32_t* n);

DPS_Status CBOR_DecodeUint(DPS_Buffer* buffer, uint64_t* n);

DPS_Status CBOR_DecodeInt(DPS_Buffer* buffer, int64_t* i);

DPS_Status CBOR_DecodeInt8(DPS_Buffer* buffer, int8_t* n);

DPS_Status CBOR_DecodeInt16(DPS_Buffer* buffer, int16_t* n);

DPS_Status CBOR_DecodeInt32(DPS_Buffer* buffer, int32_t* n);

DPS_Status CBOR_DecodeMap(DPS_Buffer* buffer, size_t* size);

DPS_Status CBOR_DecodeTag(DPS_Buffer* buffer, uint64_t* n);

DPS_Status CBOR_DecodeBoolean(DPS_Buffer* buffer, int* b);

DPS_Status CBOR_ReserveBytes(DPS_Buffer* buffer, size_t len, uint8_t** ptr);

/**
 * Prepare a CBOR structure to be wrapped in a bytes stream. This function
 * is used when the exact length of data to be enclosed is not know ahead
 * of time.
 *
 * @param buffer   The buffer to encode into
 * @param hintLen  Estimated size of the bytes to be wrapped
 * @param wrapPtr  Returns pointer to start of the byte stream
 */
DPS_Status CBOR_StartWrapBytes(DPS_Buffer* buffer, size_t hintLen, uint8_t** wrapPtr);

/**
 * Finalize byte stream wrapping of a CBOR encode structure by fixing
 * up the actual length and if necessary moving the data
 *
 * @param buffer   The buffer to encode into
 * @param wrapPtr  The pointer that was returned by CBOR_StartWrapBytes
 */
DPS_Status CBOR_EndWrapBytes(DPS_Buffer* buffer, uint8_t* wrapPtr);

/*
 * For symmetry with CBOR_DecodeInt8()
 */
#define CBOR_EncodeInt8(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/*
 * For symmetry with CBOR_DecodeInt16()
 */
#define CBOR_EncodeInt16(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/*
 * For symmetry with CBOR_DecodeInt32()
 */
#define CBOR_EncodeInt32(buffer, n) CBOR_EncodeInt(buffer, (int64_t)n)

/*
 * For symmetry with CBOR_DecodeUint8()
 */
#define CBOR_EncodeUint8(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/*
 * For symmetry with CBOR_DecodeUint16()
 */
#define CBOR_EncodeUint16(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/*
 * For symmetry with CBOR_DecodeUint32()
 */
#define CBOR_EncodeUint32(buffer, n) CBOR_EncodeUint(buffer, (uint64_t)n)

/**
 *
 * @param buffer  Buffer to decode from
 * @param data    Returns pointer into buffer storage to the decoded bytes
 * @param size    Returns length of the decoded bytes
 *
 * @return - DPS_OK if the bytes were decoded
 *         - DPS_ERR_INVALID if the major is not byte string
 *         - DPS_ERR_EOD if there was insufficient data in the buffer
 *
 */
DPS_Status CBOR_DecodeBytes(DPS_Buffer* buffer, uint8_t** data, size_t* size);

/**
 *
 * @param buffer  Buffer to decode from
 * @param data    Returns pointer into buffer storage to the decoded string
 * @param size    Returns length of the decoded string
 *
 * @return - DPS_OK if the string was decoded
 *         - DPS_ERR_INVALID if the major is not string
 *         - DPS_ERR_EOD if there was insufficient data in the buffer
 *
 */
DPS_Status CBOR_DecodeString(DPS_Buffer* buffer, char** data, size_t* size);

/**
 *
 * @param buffer  Buffer to decode from
 * @param size    Returns number of array items
 *
 * @return - DPS_OK if the array was decoded
 *         - DPS_ERR_INVALID if the major is not an array
 *         - DPS_ERR_EOD if there was insufficient data in the buffer
 *
 */
DPS_Status CBOR_DecodeArray(DPS_Buffer* buffer, size_t* size);

/**
 *
 * @param buffer  Buffer to decode from
 * @param maj     Returns the major type of the value skipped
 * @param size    Returns number of bytes skipped
 *
 * @return - DPS_OK if the array was decoded
 *         - DPS_ERR_EOD if there was insufficient data in the buffer
 *
 */
DPS_Status CBOR_Skip(DPS_Buffer* buffer, uint8_t* maj, size_t* size);

/**
 * Structure for holding state while parsing a map
 */
typedef struct {
    DPS_Buffer* buffer;   /** buffer being parsed */
    const int32_t* keys;  /** array of remaining keys to match */
    size_t needKeys;      /** remaining number of unmatched keys */
    size_t entries;       /** remaining entries in map */
} CBOR_MapState;

/**
 * Helper function for matching keys in a map. The keys must be signed integers and
 * fit in 32 bits. The keys must be in ascending order in the keys array and in the
 * map being parsed.
 *
 * @param mapState  Map state struct to initialize
 * @param buffer    Buffer to parse from
 * @param keys      Array of keys to be matched
 * @param numkeys   The number of keys to match
 */
DPS_Status DPS_ParseMapInit(CBOR_MapState* mapState, DPS_Buffer* buffer, const int32_t* keys, size_t numKeys);

/**
 * Find the next matching key and return it. The value for the key can be
 * decoded from the buffer.
 *
 * @param mapState  Map state struct
 * @param key       Returns the key that was matched
 *
 * @return - DPS_OK if the required key was matched
 *         - DPS_ERR_MISSING if a required key was not found
 *         - other errors if the CBOR was invalid
 */
DPS_Status DPS_ParseMapNext(CBOR_MapState* mapState, int32_t* key);

/**
 * Macro for checking that a map has been completely parsed
 */
#define DPS_ParseMapDone(m)  ((m)->needKeys == 0)

void CBOR_Dump(uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
