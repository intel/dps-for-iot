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
#include <float.h>
#include <math.h>
#include <safe_lib.h>
#include <stdint.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/private/cbor.h>

#if CBOR_MAX_STRING_LEN >= RSIZE_MAX_STR
#error CBOR_MAX_STRING_LEN must be less than RSIZE_MAX_STR (see safe_str_lib.h)
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

#define CBOR_LEN1   24
#define CBOR_LEN2   25
#define CBOR_LEN4   26
#define CBOR_LEN8   27

/*
 * CBOR major opcodes that encode a length
 */
#define MAJOR_ENCODES_LENGTH(m) ((m) == CBOR_BYTES || (m) == CBOR_STRING || (m) == CBOR_ARRAY || (m) == CBOR_MAP)


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

static DPS_Status EncodeUint(DPS_TxBuffer* buffer, uint64_t n, uint8_t maj)
{
    uint8_t* p = buffer->txPos;
    uint32_t lenReq = (uint32_t)Requires(n);

    if ((lenReq + 1) > DPS_TxBufferSpace(buffer)) {
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
    buffer->txPos = p;
    return DPS_OK;
}

DPS_Status CBOR_EncodeLength(DPS_TxBuffer* buffer, uint64_t len, uint8_t maj)
{
    return EncodeUint(buffer, len, maj);
}

DPS_Status CBOR_Copy(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_OK;
    if (data && len) {
        if (memcpy_s(buffer->txPos, DPS_TxBufferSpace(buffer), data, len) != EOK) {
            ret = DPS_ERR_OVERFLOW;
        } else {
            buffer->txPos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeBoolean(DPS_RxBuffer* buffer, int* i)
{
    if (DPS_RxBufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    } else {
        uint8_t b = *buffer->rxPos++;
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

static DPS_Status PeekUint(DPS_RxBuffer* buffer, uint64_t* n, uint8_t* maj, size_t* len)
{
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* p = buffer->rxPos;
    uint8_t info;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = *p;
    *maj = info & 0xE0;
    info &= 0x1F;
    *len = IntLengths[info];
    if (avail < *len) {
        return DPS_ERR_EOD;
    }
    switch (*len) {
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
    return DPS_OK;
}

static DPS_Status DecodeUint(DPS_RxBuffer* buffer, uint64_t* n, uint8_t expectMaj)
{
    DPS_Status ret;
    uint8_t maj;
    size_t len;

    ret = PeekUint(buffer, n, &maj, &len);
    if (ret == DPS_OK) {
        if (maj != expectMaj) {
            return DPS_ERR_INVALID;
        }
        buffer->rxPos += len;
    }
    return ret;
}

DPS_Status CBOR_EncodeBoolean(DPS_TxBuffer* buffer, int i)
{
    if (DPS_TxBufferSpace(buffer) < 1) {
        return DPS_ERR_OVERFLOW;
    }
    *(buffer->txPos++) = i ? CBOR_TRUE : CBOR_FALSE;
    return DPS_OK;
}

DPS_Status CBOR_EncodeUint(DPS_TxBuffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_UINT);
}

size_t _CBOR_SizeOfInt(int64_t i)
{
    if (i >= 0) {
        return CBOR_SIZEOF_LEN((uint64_t)i);
    } else {
        return CBOR_SIZEOF_LEN(~(uint64_t)i);
    }
}

DPS_Status CBOR_EncodeInt(DPS_TxBuffer* buffer, int64_t i)
{
    if (i >= 0) {
        return EncodeUint(buffer, (uint64_t)i, CBOR_UINT);
    } else {
        return EncodeUint(buffer, ~(uint64_t)i, CBOR_NEG);
    }
}

DPS_Status CBOR_EncodeBytes(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buffer, data, len);
    }
    return ret;
}

DPS_Status CBOR_ReserveBytes(DPS_TxBuffer* buffer, size_t len, uint8_t** ptr)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        if (DPS_TxBufferSpace(buffer) < len) {
            ret = DPS_ERR_OVERFLOW;
        } else {
            *ptr = buffer->txPos;
            buffer->txPos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_StartWrapBytes(DPS_TxBuffer* buffer, size_t hintLen, uint8_t** ptr)
{
    DPS_Status ret;
    uint8_t* tmp;

    *ptr = buffer->txPos;
    ret = CBOR_ReserveBytes(buffer, hintLen, &tmp);
    if (ret == DPS_OK) {
        buffer->txPos = tmp;
    }
    return ret;
}

DPS_Status CBOR_EndWrapBytes(DPS_TxBuffer* buffer, uint8_t* wrapPtr)
{
    uint8_t* pos;
    uint64_t hint;
    size_t actual;
    int diff;
    DPS_RxBuffer rx;

    /*
     * Decode the original hint length
     */
    DPS_RxBufferInit(&rx, wrapPtr, CBOR_MAX_LENGTH);
    if ((DecodeUint(&rx, &hint, CBOR_BYTES) != DPS_OK)) {
        return DPS_ERR_INVALID;
    }
    /*
     * See if the space needed to encode length changed
     */
    actual = buffer->txPos - rx.rxPos;
    diff = Requires(actual) - Requires(hint);
    if (diff && actual) {
        buffer->txPos = wrapPtr + Requires(actual);
        if (memmove_s(rx.rxPos + diff, DPS_TxBufferSpace(buffer), rx.rxPos, actual) != EOK) {
            return DPS_ERR_RESOURCES;
        }
    }
    /*
     * Rewind to write the actual length
     */
    buffer->txPos = wrapPtr;
    return CBOR_ReserveBytes(buffer, actual, &pos);
}

DPS_Status CBOR_EncodeString(DPS_TxBuffer* buffer, const char* str)
{
    DPS_Status ret;
    size_t len = str ? strnlen_s(str, CBOR_MAX_STRING_LEN + 1) : 0;

    if (len > CBOR_MAX_STRING_LEN) {
        ret = DPS_ERR_OVERFLOW;
    } else {
        ret = EncodeUint(buffer, (uint32_t)len, CBOR_STRING);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buffer, (uint8_t*)str, len);
    }
    return ret;
}

DPS_Status CBOR_EncodeStringAndLength(DPS_TxBuffer* buffer, const char* str, size_t len)
{
    DPS_Status ret;

    ret = EncodeUint(buffer, (uint32_t)len, CBOR_STRING);
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buffer, (uint8_t*)str, len);
    }
    return ret;
}

DPS_Status CBOR_EncodeArray(DPS_TxBuffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_ARRAY);
}

DPS_Status CBOR_EncodeMap(DPS_TxBuffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_MAP);
}

DPS_Status CBOR_EncodeTag(DPS_TxBuffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_TAG);
}

DPS_Status CBOR_EncodeNull(DPS_TxBuffer* buffer)
{
    if (DPS_TxBufferSpace(buffer) < 1) {
        return DPS_ERR_OVERFLOW;
    }
    *(buffer->txPos++) = CBOR_NULL;
    return DPS_OK;
}

DPS_Status CBOR_EncodeFloat(DPS_TxBuffer* buffer, float f)
{
    uint8_t* p = buffer->txPos;
    uint8_t* pf;

    if (DPS_TxBufferSpace(buffer) < 5) {
        return DPS_ERR_OVERFLOW;
    }
    *p++ = CBOR_FLOAT;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pf = (uint8_t*)&f + sizeof(float);
    *p++ = *--pf;
    *p++ = *--pf;
    *p++ = *--pf;
    *p++ = *--pf;
#else
    pf = (uint8_t*)&f;
    *p++ = *pf++;
    *p++ = *pf++;
    *p++ = *pf++;
    *p++ = *pf++;
#endif
    buffer->txPos = p;
    return DPS_OK;
}

DPS_Status CBOR_EncodeDouble(DPS_TxBuffer* buffer, double d)
{
    uint8_t* p = buffer->txPos;
    uint8_t* pd;

    if (DPS_TxBufferSpace(buffer) < 9) {
        return DPS_ERR_OVERFLOW;
    }
    *p++ = CBOR_DOUBLE;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pd = (uint8_t*)&d + sizeof(d);
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
    *p++ = *--pd;
#else
    pd = (uint8_t*)&d + sizeof(d);
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
    *p++ = *pd++;
#endif
    buffer->txPos = p;
    return DPS_OK;
}

DPS_Status CBOR_DecodeUint(DPS_RxBuffer* buffer, uint64_t* n)
{
    return DecodeUint(buffer, n, CBOR_UINT);
}

DPS_Status CBOR_DecodeUint8(DPS_RxBuffer* buffer, uint8_t* n)
{
    uint64_t u64 = 0;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, CBOR_UINT);
    if (ret != DPS_OK) {
        return ret;
    }
    if (u64 > UINT8_MAX) {
        return DPS_ERR_RANGE;
    }
    *n = (uint8_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint16(DPS_RxBuffer* buffer, uint16_t* n)
{
    uint64_t u64 = 0;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, CBOR_UINT);
    if (ret != DPS_OK) {
        return ret;
    }
    if (u64 > UINT16_MAX) {
        return DPS_ERR_RANGE;
    }
    *n = (uint16_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint32(DPS_RxBuffer* buffer, uint32_t* n)
{
    uint64_t u64 = 0;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, CBOR_UINT);
    if (ret != DPS_OK) {
        return ret;
    }
    if (u64 > UINT32_MAX) {
        return DPS_ERR_RANGE;
    }
    *n = (uint32_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeInt(DPS_RxBuffer* buffer, int64_t* i)
{
    uint8_t maj;
    size_t len;
    uint64_t n = 0;
    DPS_Status ret;

    ret = PeekUint(buffer, &n, &maj, &len);
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
        buffer->rxPos += len;
    }
    return ret;
}

DPS_Status CBOR_DecodeInt8(DPS_RxBuffer* buffer, int8_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT8_MIN) || (i64 > INT8_MAX))) {
        return DPS_ERR_RANGE;
    }
    *n = (int8_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt16(DPS_RxBuffer* buffer, int16_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT16_MIN) || (i64 > INT16_MAX))) {
        return DPS_ERR_RANGE;
    }
    *n = (int16_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt32(DPS_RxBuffer* buffer, int32_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT32_MIN) || (i64 > INT32_MAX))) {
        return DPS_ERR_RANGE;
    }
    *n = (int32_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeBytes(DPS_RxBuffer* buffer, uint8_t** data, size_t* size)
{
    DPS_Status ret;
    uint64_t len;

    *data = NULL;
    *size = 0;
    ret = DecodeUint(buffer, &len, CBOR_BYTES);
    if (ret == DPS_OK) {
        if (len > DPS_RxBufferAvail(buffer)) {
            ret = DPS_ERR_INVALID;
        } else {
            if (len) {
                *data = buffer->rxPos;
                *size = len;
                buffer->rxPos += len;
            }
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeString(DPS_RxBuffer* buffer, char** data, size_t* size)
{
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, CBOR_STRING);
    if (ret == DPS_OK) {
        if (len > DPS_RxBufferAvail(buffer)) {
            ret = DPS_ERR_INVALID;
        } else if (len > 0) {
            *data = (char*)buffer->rxPos;
            *size = len;
            buffer->rxPos += len;
        } else {
            *data = NULL;
            *size = 0;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeArray(DPS_RxBuffer* buffer, size_t* size)
{
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, CBOR_ARRAY);
    if (ret == DPS_OK) {
        *size = len;
    }
    return ret;
}

DPS_Status CBOR_DecodeMap(DPS_RxBuffer* buffer, size_t* size)
{
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, CBOR_MAP);
    if (ret == DPS_OK) {
        *size = len;
    }
    return ret;
}

DPS_Status CBOR_DecodeTag(DPS_RxBuffer* buffer, uint64_t* n)
{
    uint8_t* pos = buffer->rxPos;
    DPS_Status ret;

    ret = DecodeUint(buffer, n, CBOR_TAG);
    if (ret != DPS_OK) {
        /* Tags are optional so if this is not a tag reset the buffer */
        buffer->rxPos = pos;
    }
    return ret;
}

DPS_Status CBOR_DecodeFloat(DPS_RxBuffer* buffer, float* f)
{
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* p = buffer->rxPos;
    uint8_t* pf;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    if (*p != CBOR_FLOAT) {
        DPS_Status status = DPS_ERR_INVALID;
        uint8_t maj = *p & 0xE0;
        if (*p == CBOR_DOUBLE) {
            double d;
            status = CBOR_DecodeDouble(buffer, &d);
            if (status == DPS_OK) {
                if (fabs(d) > FLT_MAX) {
                    status = DPS_ERR_RANGE;
                } else {
                    *f = (float)d;
                    if (d != (double)*f) {
                        status = DPS_ERR_LOST_PRECISION;
                    }
                }
            }
        } else if (maj == CBOR_UINT) {
            uint64_t u64;
            status = CBOR_DecodeUint(buffer, &u64);
            if (status == DPS_OK) {
                *f = (float)u64;
                if ((uint64_t)*f != u64) {
                    status = DPS_ERR_LOST_PRECISION;
                }
            }
        } else if (maj == CBOR_NEG) {
            int64_t i64;
            status = CBOR_DecodeInt(buffer, &i64);
            if (status == DPS_OK) {
                *f = (float)i64;
                if ((int64_t)*f != i64) {
                    status = DPS_ERR_LOST_PRECISION;
                }
            }
        }
        return status;
    }
    if (avail < 5) {
        return DPS_ERR_EOD;
    }
    ++p;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pf = (uint8_t*)f + sizeof(float);
    *--pf = *p++;
    *--pf = *p++;
    *--pf = *p++;
    *--pf = *p++;
#else
    pf = (uint8_t*)f;
    *pf++ = *p++;
    *pf++ = *p++;
    *pf++ = *p++;
    *pf++ = *p++;
#endif
    buffer->rxPos = p;
    return DPS_OK;
}

DPS_Status CBOR_DecodeDouble(DPS_RxBuffer* buffer, double* d)
{
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* p = buffer->rxPos;
    uint8_t* pd;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    if (*p != CBOR_DOUBLE) {
        DPS_Status status = DPS_ERR_INVALID;
        uint8_t maj = *p & 0xE0;
        if (*p == CBOR_FLOAT) {
            float f;
            status = CBOR_DecodeFloat(buffer, &f);
            if (status == DPS_OK || status == DPS_ERR_LOST_PRECISION) {
                *d = f;
            }
        } else if (maj == CBOR_UINT) {
            uint64_t u64;
            status = CBOR_DecodeUint(buffer, &u64);
            if (status == DPS_OK) {
                *d = (double)u64;
                if ((uint64_t)*d != u64) {
                    status = DPS_ERR_LOST_PRECISION;
                }
            }
        } else if (maj == CBOR_NEG) {
            int64_t i64;
            status = CBOR_DecodeInt(buffer, &i64);
            if (status == DPS_OK) {
                *d = (double)i64;
                if ((int64_t)*d != i64) {
                    status = DPS_ERR_LOST_PRECISION;
                }
            }
        }
        return status;
    }
    if (avail < 9) {
        return DPS_ERR_EOD;
    }
    ++p;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pd = (uint8_t*)d + sizeof(double);
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
    *--pd = *p++;
#else
    pd = (uint8_t*)d;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
    *pd++ = *p++;
#endif
    buffer->rxPos = p;
    return DPS_OK;
}

DPS_Status CBOR_Peek(DPS_RxBuffer* buffer, uint8_t* majOut, uint64_t* infoOut)
{
    DPS_Status ret;
    uint64_t info;
    size_t len;
    size_t avail = DPS_RxBufferAvail(buffer);

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    if (!majOut) {
        return DPS_ERR_ARGS;
    }
    ret = PeekUint(buffer, &info, majOut, &len);
    /* For values encoding a length do a sanity check */
    if ((ret == DPS_OK) && MAJOR_ENCODES_LENGTH(*majOut) && (info >= avail)) {
        ret = DPS_ERR_INVALID;
    }
    if (infoOut && (ret == DPS_OK)) {
        *infoOut = info;
    }
    return ret;
}

DPS_Status CBOR_Skip(DPS_RxBuffer* buffer, uint8_t* majOut, size_t* skipped)
{
    DPS_Status ret = DPS_OK;
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* startPos = buffer->rxPos;
    uint64_t len = 0;
    size_t size = 0;
    uint8_t* unused;
    uint8_t info;
    uint8_t maj;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = buffer->rxPos[0];
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
            buffer->rxPos += len;
        }
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &unused, &size);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&unused, &size);
        break;
    case CBOR_ARRAY:
        ret = DecodeUint(buffer, &len, maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
        }
        break;
    case CBOR_MAP:
        ret = DecodeUint(buffer, &len, maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
            if (ret == DPS_OK) {
                ret = CBOR_Skip(buffer, NULL, NULL);
            }
        }
        break;
    case CBOR_OTHER:
        if (20 <= info && info <= 22) {
            buffer->rxPos += 1;
        } else if (info == 26) {
            float unused;
            ret = CBOR_DecodeFloat(buffer, &unused);
        } else if (info == 27) {
            double unused;
            ret = CBOR_DecodeDouble(buffer, &unused);
        } else {
            ret = DPS_ERR_INVALID;
        }
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    if (skipped) {
        *skipped = buffer->rxPos - startPos;
    }
    if (majOut) {
        *majOut = maj;
    }
    return ret;
}

size_t _CBOR_SizeOfString(const char* s)
{
    size_t len = s ? strnlen_s(s, CBOR_MAX_STRING_LEN + 1) : 0;
    return len + CBOR_SIZEOF_LEN(len);
}

DPS_Status DPS_ParseMapInit(CBOR_MapState* mapState, DPS_RxBuffer* buffer, const int32_t* keys, size_t numKeys,
        const int32_t* optKeys, size_t numOptKeys)
{
    mapState->buffer = buffer;
    mapState->needs = keys;
    mapState->needKeys = numKeys;
    mapState->wants = optKeys;
    mapState->wantKeys = numOptKeys;
    mapState->result = CBOR_DecodeMap(buffer, &mapState->entries);
    return mapState->result;
}

DPS_Status DPS_ParseMapNext(CBOR_MapState* mapState, int32_t* key)
{
    int32_t k = 0;

    if (mapState->result != DPS_OK) {
        return mapState->result;
    }
    mapState->result = DPS_ERR_MISSING;
    while (mapState->entries && (mapState->needKeys || mapState->wantKeys)) {
        --mapState->entries;
        mapState->result = CBOR_DecodeInt32(mapState->buffer, &k);
        if (mapState->result != DPS_OK) {
            break;
        }
        if (mapState->needKeys) {
            if (k < mapState->needs[0]) {
                /*
                 * Nothing to do
                 */
            } else if (k == mapState->needs[0]) {
                ++mapState->needs;
                --mapState->needKeys;
                *key = k;
                goto Exit;
            } else {
                /*
                 * Keys must be in ascending order
                 */
                mapState->result = DPS_ERR_MISSING;
                break;
            }
        }
        while (mapState->wantKeys) {
            if (k < mapState->wants[0]) {
                break;
            } else if (k == mapState->wants[0]) {
                ++mapState->wants;
                --mapState->wantKeys;
                *key = k;
                goto Exit;
            } else {
                ++mapState->wants;
                --mapState->wantKeys;
            }
        }
        /*
         * Skip map entries for keys we are not looking for
         */
        mapState->result = CBOR_Skip(mapState->buffer, NULL, NULL);
        if (mapState->result != DPS_OK) {
            break;
        }
    }
Exit:
    if (mapState->result != DPS_OK) {
        return mapState->result;
    }
    if (mapState->needKeys) {
        /*
         * We expect there to be more entries
         */
        if (!mapState->entries) {
            mapState->result = DPS_ERR_MISSING;
        }
    }
    return mapState->result;
}

int DPS_ParseMapDone(CBOR_MapState* mapState)
{
    int32_t k;

    if (mapState->needKeys) {
        return DPS_FALSE;
    } else if (mapState->wantKeys && mapState->entries) {
        return DPS_FALSE;
    } else {
        while (mapState->entries) {
            /*
             * We have all the keys we need so skip all remaining entries
             */
            --mapState->entries;
            mapState->result = CBOR_DecodeInt32(mapState->buffer, &k);
            if (mapState->result == DPS_OK) {
                mapState->result = CBOR_Skip(mapState->buffer, NULL, NULL);
            }
            if (mapState->result != DPS_OK) {
                return DPS_FALSE;
            }
        }
        return DPS_TRUE;
    }
}

#ifdef DPS_DEBUG
static DPS_Status Dump(DPS_RxBuffer* buffer, int in)
{
    static const char indent[] = "                                                            ";
    DPS_Status ret = DPS_OK;
    size_t size = 0;
    uint64_t len;
    uint8_t* unused;
    uint8_t maj;
    uint64_t n;
    float f;
    double d;

    if (DPS_RxBufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    }
    maj = buffer->rxPos[0] & 0xE0;
    switch (maj) {
    case CBOR_UINT:
        ret = DecodeUint(buffer, &n, maj);
        DPS_PRINT("%.*suint:%zu\n", in, indent, n);
        break;
    case CBOR_NEG:
        ret = DecodeUint(buffer, &n, maj);
        DPS_PRINT("%.*sint:-%zu\n", in, indent, n);
        break;
    case CBOR_TAG:
        ret = DecodeUint(buffer, &n, maj);
        DPS_PRINT("%.*stag:%zu\n", in, indent, n);
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &unused, &size);
        DPS_PRINT("%.*sbstr: len=%zu\n", in, indent, size);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&unused, &size);
        DPS_PRINT("%.*sstring: \"%.*s\"\n", in, indent, (int)size, unused);
        break;
    case CBOR_ARRAY:
        DPS_PRINT("%.*s[\n", in, indent);
        ret = DecodeUint(buffer, &len, maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
        }
        DPS_PRINT("%.*s]\n", in, indent);
        break;
    case CBOR_MAP:
        DPS_PRINT("%.*s{\n", in, indent);
        ret = DecodeUint(buffer, &len, maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
            if (ret == DPS_OK) {
                ret = Dump(buffer, in + 4);
            }
        }
        DPS_PRINT("%.*s}\n", in, indent);
        break;
    case CBOR_OTHER:
        if (buffer->rxPos[0] == CBOR_TRUE) {
            DPS_PRINT("%.*sTRUE\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        if (buffer->rxPos[0] == CBOR_FALSE) {
            DPS_PRINT("%.*sFALSE\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        if (buffer->rxPos[0] == CBOR_NULL) {
            DPS_PRINT("%.*sNULL\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        if (buffer->rxPos[0] == CBOR_FLOAT) {
            ret = CBOR_DecodeFloat(buffer, &f);
            DPS_PRINT("%.*sfloat:%f\n", in, indent, f);
            break;
        }
        if (buffer->rxPos[0] == CBOR_DOUBLE) {
            ret = CBOR_DecodeDouble(buffer, &d);
            DPS_PRINT("%.*sdouble:%f\n", in, indent, d);
            break;
        }
        ret = DPS_ERR_INVALID;
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void CBOR_Dump(const char* tag, uint8_t* data, size_t len)
{
    if (DPS_DEBUG_ENABLED()) {
        DPS_Status ret;
        DPS_RxBuffer tmp;

        if (tag) {
            DPS_PRINT("CBOR %s:\n", tag);
        }
        DPS_RxBufferInit(&tmp, data, len);
        while (DPS_RxBufferAvail(&tmp)) {
            ret = Dump(&tmp, 0);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Invalid CBOR at offset %d\n", (int)(tmp.rxPos - tmp.base));
                break;
            }
        }
    }
}
#endif

