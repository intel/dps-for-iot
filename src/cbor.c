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

#include <dps/dbg.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "cbor.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

#define CBOR_LEN1   24
#define CBOR_LEN2   25
#define CBOR_LEN4   26
#define CBOR_LEN8   27

#define CBOR_FALSE  (CBOR_OTHER | 20)
#define CBOR_TRUE   (CBOR_OTHER | 21)
#define CBOR_NULL   (CBOR_OTHER | 22)

static int Requires(uint64_t n)
{
    if (n < 24) {
        return 0;
    }
    if (n <= UINT8_MAX) {
        return 1;
    }
    if (n <= UINT16_MAX) {
        return 2;
    }
    if (n <= UINT32_MAX) {
        return 4;
    }
    return 8;
}

static DPS_Status EncodeUint(DPS_Buffer* buffer, uint64_t n, uint8_t maj)
{
    uint8_t* p = buffer->pos;
    int lenReq = Requires(n);

    if ((lenReq + 1) > DPS_BufferSpace(buffer)) {
        return DPS_ERR_OVERFLOW;
    }
    switch (lenReq) {
        case 0:
            *p++ = (uint8_t)(maj | n);
            break;
        case 1:
            *p++ = (uint8_t)(maj | CBOR_LEN1);
            *p++ = (uint8_t)(n);
            break;
        case 2:
            *p++ = (uint8_t)(maj | CBOR_LEN2);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
            break;
        case 4:
            *p++ = (uint8_t)(maj | CBOR_LEN4);
            *p++ = (uint8_t)(n >> 24);
            *p++ = (uint8_t)(n >> 16);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
            break;
        case 8:
            *p++ = (uint8_t)(maj | CBOR_LEN8);
            *p++ = (uint8_t)(n >> 56);
            *p++ = (uint8_t)(n >> 48);
            *p++ = (uint8_t)(n >> 40);
            *p++ = (uint8_t)(n >> 32);
            *p++ = (uint8_t)(n >> 24);
            *p++ = (uint8_t)(n >> 16);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
    }
    buffer->pos = p;
    return DPS_OK;
}

DPS_Status CBOR_EncodeLength(DPS_Buffer* buffer, uint64_t len, uint8_t maj)
{
    return EncodeUint(buffer, len, maj);
}

DPS_Status CBOR_Copy(DPS_Buffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_OK;
    if (DPS_BufferSpace(buffer) < len) {
        ret = DPS_ERR_OVERFLOW;
    } else if (data) {
        memcpy(buffer->pos, data, len);
        buffer->pos += len;
    }
    return ret;
}

DPS_Status CBOR_DecodeBoolean(DPS_Buffer* buffer, int* i)
{
    if (DPS_BufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    } else {
        uint8_t b = *buffer->pos++;
        if (b != CBOR_FALSE && b != CBOR_TRUE) {
            return DPS_ERR_INVALID;
        }
        *i = b & 1;
        return DPS_OK;
    }
}

/*
 * Byte length corresponding the various info encodings
 */
static const size_t IntLengths[] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,3,5,9,0,0,0,0 };

static DPS_Status DecodeUint(DPS_Buffer* buffer, uint64_t* n, uint8_t* maj)
{
    size_t avail = DPS_BufferAvail(buffer);
    uint8_t* p = buffer->pos;
    uint8_t info;
    size_t len;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = *p;
    *maj = info & 0xE0;
    info &= 0x1F;
    len = IntLengths[info];
    if (avail < len) {
        return DPS_ERR_EOD;
    }
    switch (len) {
    case 1:
        *n = info;
        break;
    case 2:
        *n = (uint64_t)p[1];
        break;
    case 3:
        *n = ((uint64_t)p[1] << 8) | (uint64_t)p[2];
        break;
    case 5:
        *n = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3]) << 8 | (uint64_t)p[4];
        break;
    case 9:
        *n = ((uint64_t)p[1] << 56) | ((uint64_t)p[2] << 48) | ((uint64_t)p[3] << 40) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 24) | ((uint64_t)p[6] << 16) | ((uint64_t)p[7] << 8) | (uint64_t)p[8];
        break;
    default:
        return DPS_ERR_INVALID;
    }
    buffer->pos += len;
    return DPS_OK;
}

DPS_Status CBOR_EncodeBoolean(DPS_Buffer* buffer, int i)
{
    if (DPS_BufferSpace(buffer) < 1) {
        return DPS_ERR_OVERFLOW;
    }
    *(buffer->pos++) = i ? CBOR_TRUE : CBOR_FALSE;
    return DPS_OK;
}

DPS_Status CBOR_EncodeUint(DPS_Buffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_UINT);
}

DPS_Status CBOR_EncodeInt(DPS_Buffer* buffer, int64_t i)
{
    if (i >= 0) {
        return EncodeUint(buffer, (uint64_t)i, CBOR_UINT);
    } else {
        return EncodeUint(buffer, ~(uint64_t)i, CBOR_NEG);
    }
}

DPS_Status CBOR_EncodeBytes(DPS_Buffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        if (DPS_BufferSpace(buffer) < len) {
            ret = DPS_ERR_OVERFLOW;
        } else if (data) {
            memcpy(buffer->pos, data, len);
            buffer->pos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_ReserveBytes(DPS_Buffer* buffer, size_t len, uint8_t** ptr)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        if (DPS_BufferSpace(buffer) < len) {
            ret = DPS_ERR_OVERFLOW;
        } else {
            *ptr = buffer->pos;
            buffer->pos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_StartWrapBytes(DPS_Buffer* buffer, size_t hintLen, uint8_t** ptr)
{
    DPS_Status ret;
    uint8_t* tmp;

    *ptr = buffer->pos;
    ret = CBOR_ReserveBytes(buffer, hintLen, &tmp);
    if (ret == DPS_OK) {
        buffer->pos = tmp;
    }
    return ret;
}

DPS_Status CBOR_EndWrapBytes(DPS_Buffer* buffer, uint8_t* ptr)
{
    uint8_t maj;
    uint8_t* pos = buffer->pos;
    uint64_t hint;
    size_t actual;
    int diff;

    /*
     * Rewind and decode the original hint length
     */
    buffer->pos = ptr;
    if ((DecodeUint(buffer, &hint, &maj) != DPS_OK) || (maj != CBOR_BYTES)) {
        return DPS_ERR_INVALID;
    }
    /*
     * See if the length encoding changed
     */
    actual = pos - buffer->pos;
    diff = Requires(actual) - Requires(hint);
    if (diff) {
        memmove(buffer->pos + diff, buffer->pos, actual);
    }
    /*
     * Rewind again and write the new length
     */
    buffer->pos = ptr;
    return CBOR_ReserveBytes(buffer, actual, &pos);
}


DPS_Status CBOR_EncodeString(DPS_Buffer* buffer, const char* str)
{
    size_t len = strlen(str) + 1;
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_STRING);
    if (ret == DPS_OK) {
        if (DPS_BufferSpace(buffer) < len) {
            ret = DPS_ERR_OVERFLOW;
        } else if (str) {
            memcpy(buffer->pos, str, len);
            buffer->pos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_EncodeArray(DPS_Buffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_ARRAY);
}

DPS_Status CBOR_EncodeMap(DPS_Buffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_MAP);
}

DPS_Status CBOR_EncodeTag(DPS_Buffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_TAG);
}

DPS_Status CBOR_DecodeUint(DPS_Buffer* buffer, uint64_t* n)
{
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, n, &maj);
    if ((ret == DPS_OK) && (maj != CBOR_UINT)) {
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

DPS_Status CBOR_DecodeUint8(DPS_Buffer* buffer, uint8_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT8_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint8_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint16(DPS_Buffer* buffer, uint16_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT16_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint16_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint32(DPS_Buffer* buffer, uint32_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT32_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint32_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeInt(DPS_Buffer* buffer, int64_t* i)
{
    uint8_t maj;
    uint64_t n = 0;
    DPS_Status ret;

    ret = DecodeUint(buffer, &n, &maj);
    if (ret == DPS_OK) {
        if (maj == CBOR_UINT) {
            *i = (int64_t)n;
            if (*i < 0) {
                return DPS_ERR_INVALID;
            }
        } else if (maj == CBOR_NEG) {
            *i = (int64_t)(~n);
            if (*i > 0) {
                return DPS_ERR_INVALID;
            }
        } else {
            return DPS_ERR_INVALID;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeInt8(DPS_Buffer* buffer, int8_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT8_MIN) || (i64 > INT8_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int8_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt16(DPS_Buffer* buffer, int16_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT16_MIN) || (i64 > INT16_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int16_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt32(DPS_Buffer* buffer, int32_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT32_MIN) || (i64 > INT32_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int32_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeBytes(DPS_Buffer* buffer, uint8_t** data, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    *data = NULL;
    *size = 0;
    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if ((maj != CBOR_BYTES) || (len > DPS_BufferAvail(buffer))) {
            ret = DPS_ERR_INVALID;
        } else {
            if (len) {
                *data = buffer->pos;
                *size = len;
                buffer->pos += len;
            }
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeString(DPS_Buffer* buffer, char** data, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if ((maj != CBOR_STRING) || (len > DPS_BufferAvail(buffer))) {
            ret = DPS_ERR_INVALID;
        } else {
            *data = (char*)buffer->pos;
            *size = len;
            buffer->pos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeArray(DPS_Buffer* buffer, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if (maj != CBOR_ARRAY) {
            ret = DPS_ERR_INVALID;
        } else {
            *size = len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeMap(DPS_Buffer* buffer, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if (maj != CBOR_MAP) {
            ret = DPS_ERR_INVALID;
        } else {
            *size = len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeTag(DPS_Buffer* buffer, uint64_t* n)
{
    uint8_t maj;
    uint8_t* pos = buffer->pos;
    DPS_Status ret;

    ret = DecodeUint(buffer, n, &maj);
    if ((ret == DPS_OK) && (maj != CBOR_TAG)) {
        buffer->pos = pos;
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

DPS_Status CBOR_Skip(DPS_Buffer* buffer, uint8_t* majOut, size_t* size)
{
    DPS_Status ret = DPS_OK;
    size_t avail = DPS_BufferAvail(buffer);
    uint8_t* startPos = buffer->pos;
    size_t len = 0;
    uint8_t* dummy;
    uint8_t info;
    uint8_t maj;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = buffer->pos[0];
    maj = info & 0xE0;
    info &= 0x1F;

    switch (maj) {
    case CBOR_UINT:
    case CBOR_NEG:
    case CBOR_TAG:
        len = IntLengths[info];
        if (len == 0) {
            ret = DPS_ERR_INVALID;
        } else if (avail < len) {
            ret = DPS_ERR_EOD;
        } else {
            buffer->pos += len;
        }
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &dummy, &len);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&dummy, &len);
        break;
    case CBOR_ARRAY:
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
        }
        break;
    case CBOR_MAP:
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
            if (ret == DPS_OK) {
                ret = CBOR_Skip(buffer, NULL, NULL);
            }
        }
        break;
    case CBOR_OTHER:
        if (info < 20 || info > 22) {
            ret = DPS_ERR_INVALID;
        } else {
            buffer->pos += 1;
        }
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    if (size) {
        *size = buffer->pos - startPos;
    }
    if (majOut) {
        *majOut = maj;
    }
    return ret;
}

size_t _CBOR_SizeOfString(const char* s)
{
    size_t l = strlen(s) + 1;
    return l + CBOR_SIZEOF_LEN(l);
}

DPS_Status DPS_ParseMapInit(CBOR_MapState* mapState, DPS_Buffer* buffer, const int32_t* keys, size_t numKeys)
{
    mapState->buffer = buffer;
    mapState->keys = keys;
    mapState->needKeys = numKeys;
    return CBOR_DecodeMap(buffer, &mapState->entries);
}

DPS_Status DPS_ParseMapNext(CBOR_MapState* mapState, int32_t* key)
{
    DPS_Status ret = DPS_ERR_MISSING;
    int32_t k = 0;

    while (mapState->entries && mapState->needKeys) {
        --mapState->entries;
        ret = CBOR_DecodeInt32(mapState->buffer, &k);
        if (ret != DPS_OK) {
            break;
        }
        if (k == mapState->keys[0]) {
            ++mapState->keys;
            --mapState->needKeys;
            *key = k;
            break;
        }
        /*
         * Keys must be in ascending order
         */
        if (k > mapState->keys[0]) {
            ret = DPS_ERR_MISSING;
            break;
        }
        /*
         * Skip map entries for keys we are not looking for
         */
        ret = CBOR_Skip(mapState->buffer, NULL, NULL);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        return ret;
    }
    if (mapState->needKeys) {
        /*
         * We expect there to be more entries
         */
        if (!mapState->entries) {
            ret = DPS_ERR_MISSING;
        }
    } else {
        /*
         * We have all the keys we need so skip all remaining entries
         */
        while (mapState->entries) {
            --mapState->entries;
            ret = CBOR_DecodeInt32(mapState->buffer, &k);
            if (ret == DPS_OK) {
                ret = CBOR_Skip(mapState->buffer, NULL, NULL);
            }
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    return ret;
}

static DPS_Status Dump(DPS_Buffer* buffer, int in)
{
    static const char indent[] = "                                                            ";
    DPS_Status ret = DPS_OK;
    size_t len = 0;
    uint8_t* dummy;
    uint8_t maj;
    uint64_t n;

    if (DPS_BufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    }
    switch(buffer->pos[0] & 0xE0) {
    case CBOR_UINT:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*suint:%zu\n", in, indent, n);
        break;
    case CBOR_NEG:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*sint:-%zu\n", in, indent, n);
        break;
    case CBOR_TAG:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*stag:%zu\n", in, indent, n);
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &dummy, &len);
        DPS_PRINT("%.*sbstr: len=%zu\n", in, indent, len);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&dummy, &len);
        DPS_PRINT("%.*sstring: \"%.*s\"\n", in, indent, (int)len, dummy);
        break;
    case CBOR_ARRAY:
        DPS_PRINT("%.*s[\n", in, indent);
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
        }
        DPS_PRINT("%.*s]\n", in, indent);
        break;
    case CBOR_MAP:
        DPS_PRINT("%.*s{\n", in, indent);
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
            if (ret == DPS_OK) {
                ret = Dump(buffer, in + 4);
            }
        }
        DPS_PRINT("%.*s}\n", in, indent);
        break;
    case CBOR_OTHER:
        if (buffer->pos[0] == CBOR_TRUE) {
            DPS_PRINT("%.*sTRUE\n", in, indent);
            ++buffer->pos;
            break;
        }
        if (buffer->pos[0] == CBOR_FALSE) {
            DPS_PRINT("%.*sFALSE\n", in, indent);
            ++buffer->pos;
            break;
        }
        if (buffer->pos[0] == CBOR_NULL) {
            DPS_PRINT("%.*sNULL\n", in, indent);
            ++buffer->pos;
            break;
        }
        ret = DPS_ERR_INVALID;
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void CBOR_Dump(uint8_t* data, size_t len)
{
    if (DPS_DEBUG_ENABLED()) {
        DPS_Status ret;
        DPS_Buffer tmp;

        DPS_BufferInit(&tmp, data, len);
        while (DPS_BufferAvail(&tmp)) {
            ret = Dump(&tmp, 0);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Invalid CBOR at offset %d\n", (int)(tmp.pos - tmp.base));
                break;
            }
        }
    }
}

