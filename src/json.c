/**
 * @file
 * JSON <-> CBOR conversion
 */

/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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

#include <ctype.h>
#include <safe_lib.h>
#include <string.h>
#include <stdlib.h>
#include <dps/private/cbor.h>
#include <dps/dbg.h>
#include <dps/json.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

#define MAX_INPUT_STRING_LEN  (RSIZE_MAX_STR - 1)
#define JSON_MAX_STRING_LEN   CBOR_MAX_STRING_LEN

typedef struct {
    char* str;
    size_t len;
} JSONBuffer;

static DPS_Status CountItems(JSONBuffer* json, size_t* count)
{
    int empty = 1;
    int i;
    int numBrackets = 0;
    int numBraces = 0;

    if (json->str[0] == '[') {
        ++numBrackets;
    } else {
        ++numBraces;
    }
    *count = 0;

    for (i = 1; i < json->len; ++i) {
        switch (json->str[i]) {
        case '[':
            ++numBrackets;
            break;
        case ']':
            --numBrackets;
            break;
        case '{':
            ++numBraces;
            break;
        case '}':
            --numBraces;
            break;
        case ',':
            if ((numBrackets == 1 && numBraces == 0) || (numBraces == 1 && numBrackets == 0)) {
                *count += 1;
            }
            break;
        default:
            if (!isspace(json->str[i])) {
                empty = 0;
            }
            break;
        }
        if (numBrackets == 0 && numBraces == 0) {
            // handles case of [] or {}
            if (!empty) {
                *count += 1;
            }
            break;
        }
    }
    if (numBrackets != 0 || numBraces != 0) {
        // This indicates where the failure was encountered
        json->str += (i - 1);
        json->len -= (i - 1);
        return DPS_ERR_INVALID;
    } else {
        return DPS_ERR_OK;
    }
}

static DPS_Status ToCBORNumber(DPS_TxBuffer* cbor, JSONBuffer* json)
{
    char* endPtr;
    int64_t i64 = strtoll(json->str, &endPtr, 10);
    if (endPtr == json->str) {
        DPS_ERRPRINT("Invalid number\n");
        return DPS_ERR_INVALID;
    }
    if (*endPtr == '.') {
        double d = strtod(json->str, &endPtr);
        if (endPtr == json->str) {
            DPS_ERRPRINT("Invalid number\n");
            return DPS_ERR_INVALID;
        }
        json->len -= (endPtr - json->str);
        json->str = endPtr;
        return CBOR_EncodeDouble(cbor, d);
    } else {
        json->len -= (endPtr - json->str);
        json->str = endPtr;
        return CBOR_EncodeInt(cbor, i64);
    }
}

static DPS_Status ExpectStr(JSONBuffer* json, const char* str, size_t len)
{
    if (json->len < len || strncmp(json->str, str, len) != 0) {
        DPS_ERRPRINT("Expected \"%s\"\n", str);
        return DPS_ERR_INVALID;
    }
    json->len -= len;
    json->str += len;
    if (json->len && !strchr(",[]{} \n\r\t", json->str[0])) {
        DPS_ERRPRINT("Expected \"%s\"\n", str);
        return DPS_ERR_INVALID;
    }
    return DPS_OK;
}

static int TestStr(JSONBuffer* json, const char* str)
{
    size_t len = strnlen_s(str, JSON_MAX_STRING_LEN);
    if (json->len < len || strncmp(json->str, str, len) != 0) {
        return DPS_FALSE;
    } else {
        json->len -= len;
        json->str += len;
        return DPS_TRUE;
    }
}

static inline void SkipWS(JSONBuffer* json)
{
    while (json->len && isspace(json->str[0])) {
        ++json->str;
        --json->len;
    }
}

static DPS_Status ExpectChar(JSONBuffer* json, char c)
{
    SkipWS(json);
    if (json->len == 0) {
        return DPS_ERR_EOD;
    }
    if (json->str[0] != c) {
        DPS_ERRPRINT("Expected '%c' character\n", c);
        return DPS_ERR_INVALID;
    }
    ++json->str;
    --json->len;
    return DPS_OK;
}

static inline int CharToHex(uint8_t c)
{
    if (c <= '9') {
        return (uint8_t)(c - '0');
    } else {
        return 10 + (uint8_t)((c | 0x20) - 'a');
    }
}

static DPS_Status ToCBORBytes(DPS_TxBuffer* cbor, JSONBuffer* json)
{
    DPS_Status status = ExpectChar(json, ':');
    if (status == DPS_OK) {
        status = ExpectChar(json, '"');
    }
    if (status == DPS_OK) {
        uint8_t* ptr;
        size_t len;
        for (len = 0; len < json->len; ++len) {
            if (json->str[len] == '"') {
                break;
            }
        }
        if (json->str[len] != '"') {
            return DPS_ERR_INVALID;
        }
        if (len & 1) {
            DPS_ERRPRINT("Expected even number of hex characters\n");
            return DPS_ERR_INVALID;
        }
        len /= 2;
        status = CBOR_ReserveBytes(cbor, len, &ptr);
        if (status == DPS_OK) {
            while (len--) {
                int a = CharToHex(json->str[0]);
                int b = CharToHex(json->str[1]);
                if (a > 15 || b > 15) {
                    DPS_ERRPRINT("Expected hexadecimal character\n");
                    status = DPS_ERR_INVALID;
                    break;
                }
                *ptr++ = (a << 4) | b;
                json->str += 2;
                json->len -= 2;
            }
        }
        // Skip closing quote
        ++json->str;
        --json->len;
    }
    if (status == DPS_OK) {
        status = ExpectChar(json, '}');
    }
    return status;
}

static DPS_Status ToCBOR(DPS_TxBuffer* cbor, JSONBuffer* json)
{
    DPS_Status status;
    size_t len;

    SkipWS(json);
    if (json->len == 0) {
        return DPS_ERR_EOD;
    }

    switch (json->str[0]) {
    case 0:
        status = DPS_ERR_EOD;
        break;
    case '"':
        len = 0;
        --json->len;
        ++json->str;
        while (json->len--) {
            char c = json->str[len];
            // newline chars are not allowed in JSON strings
            if (c == '"' || c == '\r' || c == '\n' || c == '\0') {
                break;
            }
            ++len;
        }
        if (json->str[len] != '"') {
            status = DPS_ERR_INVALID;
        } else {
            // Encode string
            status = CBOR_EncodeLength(cbor, len, CBOR_STRING);
            if (status == DPS_OK) {
                status = CBOR_Copy(cbor, (uint8_t*)json->str, len);
            }
            json->str += len + 1;
        }
        break;
    case '[':
        status = CountItems(json, &len);
        if (status == DPS_OK) {
            ++json->str;
            --json->len;
            status = CBOR_EncodeArray(cbor, len);
        }
        while (status == DPS_OK && len--) {
            status = ToCBOR(cbor, json);
            if (len && (status == DPS_OK)) {
                status = ExpectChar(json, ',');
            }
        }
        if (status == DPS_OK) {
            status = ExpectChar(json, ']');
        }
        break;
    case '{':
        status = CountItems(json, &len);
        if (status != DPS_OK) {
            break;
        }
        ++json->str;
        --json->len;
        SkipWS(json);
        // Special case encodings
        if (TestStr(json, "\"$binary\"")) {
            if (len == 1) {
                status = ToCBORBytes(cbor, json);
            } else {
                status = DPS_ERR_INVALID;
            }
            break;
        }
        status = CBOR_EncodeMap(cbor, len);
        while (status == DPS_OK && len--) {
            // JSON requires map keys to be quoted strings
            status = ExpectChar(json, '"');
            if (status != DPS_OK) {
                break;
            }
            // Push back the '"' char
            --json->str;
            ++json->len;
            status = ToCBOR(cbor, json);
            if (status == DPS_OK) {
                status = ExpectChar(json, ':');
            }
            if (status == DPS_OK) {
                status = ToCBOR(cbor, json);
                if (len && (status == DPS_OK)) {
                    status = ExpectChar(json, ',');
                }
            }
        }
        if (status == DPS_OK) {
            status = ExpectChar(json, '}');
        }
        break;
    case 't':
        status = ExpectStr(json, "true", 4);
        if (status == DPS_OK) {
            status = CBOR_EncodeBoolean(cbor, 1);
        }
        break;
    case 'f':
        status = ExpectStr(json, "false", 5);
        if (status == DPS_OK) {
            status = CBOR_EncodeBoolean(cbor, 0);
        }
        break;
    case 'n':
        status = ExpectStr(json, "null", 4);
        if (status == DPS_OK) {
            status = CBOR_EncodeNull(cbor);
        }
        break;
    case '-':
    case '+':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        status = ToCBORNumber(cbor, json);
        break;
    default:
        status = DPS_ERR_INVALID;
        break;
    }
    return status;
}

DPS_Status DPS_JSON2CBOR(const char* json, uint8_t* cbor, size_t cborSize, size_t* cborLen)
{
    DPS_Status status;
    DPS_TxBuffer cborBuf;
    JSONBuffer jsonBuf;

    DPS_DBGTRACEA("json=%p,cbor=%p,cborSize=%d,cborLen=%p\n",
                  json, cbor, cborSize, cborLen);

    if (!json || !cbor || !cborLen) {
        return DPS_ERR_NULL;
    }
    jsonBuf.str = (char*)json;
    jsonBuf.len = strnlen_s(json, MAX_INPUT_STRING_LEN);
    // An empty string is ok
    if (jsonBuf.len == 0) {
        *cborLen = 0;
        return DPS_OK;
    }
    DPS_TxBufferInit(&cborBuf, cbor, cborSize);
    status = ToCBOR(&cborBuf, &jsonBuf);
    if (status == DPS_OK) {
        *cborLen = DPS_TxBufferUsed(&cborBuf);
    } else if (status == DPS_ERR_OVERFLOW) {
        DPS_WARNPRINT("CBOR buffer too small\n");
    } else {
        DPS_ERRPRINT("JSON2CBOR failed near character pos %d : \"%.*s\"\n", (int)(jsonBuf.str - json), 10, jsonBuf.str);
    }
    return status;
}

static DPS_Status Indent(JSONBuffer* json, int pretty, int indent)
{
    if (pretty) {
        int i;
        if (indent && json->str[-1] == ':') {
            if (json->len <= 1) {
                return DPS_ERR_OVERFLOW;
            } else {
                json->str[0] = ' ';
                json->len -= 1;
                json->str += 1;
                return DPS_OK;
            }
        }
        indent *= 2;
        if (json->len <= (indent + 1)) {
            return DPS_ERR_OVERFLOW;
        }
        json->str[0] = '\n';
        json->len -= 1;
        json->str += 1;
        for (i = 0; i < indent; ++i) {
            json->str[i] = ' ';
        }
        json->len -= indent;
        json->str += indent;
    }
    return DPS_OK;
}

static inline DPS_Status JSONAppendChar(JSONBuffer* json, char c)
{
    if (json->len < 1) {
        return DPS_ERR_OVERFLOW;
    } else {
        json->str[0] = c;
        json->str[1] = '\0';
        json->str += 1;
        json->len -= 1;
        return DPS_OK;
    }
}

static inline DPS_Status JSONAppendStr(JSONBuffer* json, const char* str)
{
    size_t sz = strnlen_s(str, JSON_MAX_STRING_LEN);
    if (memcpy_s(json->str, json->len, str, sz + 1) != EOK) {
        return DPS_ERR_OVERFLOW;
    } else {
        json->str += sz;
        json->len -= sz;
        return DPS_OK;
    }
}

static DPS_Status ToJSON(JSONBuffer* json, DPS_RxBuffer* cbor, int pretty, int indent)
{
    char numStr[64];
    char* str = numStr;
    DPS_Status status = DPS_OK;
    size_t size = 0;
    uint64_t len;
    uint8_t* bytes;
    uint8_t maj;
    int64_t i64;
    uint64_t u64;

    if (DPS_RxBufferAvail(cbor) < 1) {
        return DPS_ERR_EOD;
    }
    status = Indent(json, pretty, indent);
    if (status != DPS_OK) {
        return status;
    }
    maj = cbor->rxPos[0] & 0xE0;
    switch (maj) {
    case CBOR_TAG:
    case CBOR_UINT:
        status = CBOR_DecodeUint(cbor, &u64);
        if (status == DPS_OK) {
            size = snprintf(json->str, json->len, "%zu", u64);
            if (size >= json->len) {
                status = DPS_ERR_OVERFLOW;
            } else {
                json->len -= size;
                json->str += size;
            }
        }
        break;
    case CBOR_NEG:
        status = CBOR_DecodeInt(cbor, &i64);
        if (status == DPS_OK) {
            size = snprintf(json->str, json->len, "%zi", i64);
            if (size >= json->len) {
                status = DPS_ERR_OVERFLOW;
            } else {
                json->len -= size;
                json->str += size;
            }
        }
        break;
    case CBOR_BYTES:
        status = CBOR_DecodeBytes(cbor, &bytes, &size);
        if (status == DPS_OK) {
            status = JSONAppendChar(json, '{');
        }
        if (status == DPS_OK) {
            status = Indent(json, pretty, indent + 1);
        }
        if (status == DPS_OK) {
            status = JSONAppendStr(json, "\"$binary\":\"");
        }
        if (json->len < (size * 2)) {
            status = DPS_ERR_OVERFLOW;
        }
        if (status == DPS_OK) {
            while (size--) {
                static const char HexToChar[16] = "0123456789ABCDEF";
                json->str[0] = HexToChar[*bytes >> 4];
                json->str[1] = HexToChar[*bytes & 0xF];
                json->str += 2;
                json->len -= 2;
                bytes += 1;
            }
            status = JSONAppendChar(json, '"');
            if (status == DPS_OK) {
                status = Indent(json, pretty, indent);
            }
            if (status == DPS_OK) {
                status = JSONAppendChar(json, '}');
            }
        }
        break;
    case CBOR_STRING:
        status = CBOR_DecodeString(cbor, (char**)&str, &size);
        if ((size + 2) >= json->len) {
            status = DPS_ERR_OVERFLOW;
        } else {
            json->str[0] = '\"';
            ++json->str;
            --json->len;
            memcpy_s(json->str, json->len, str, size);
            json->str[size] = '\"';
            json->len -= size + 1;
            json->str += size + 1;
            json->str[0] = '\0';
        }
        break;
    case CBOR_ARRAY:
        status = CBOR_DecodeArray(cbor, &len);
        if (status == DPS_OK) {
            status = JSONAppendChar(json, '[');
        }
        if (status == DPS_OK) {
            while (len--) {
                status = ToJSON(json, cbor, pretty, indent + 1);
                if (status != DPS_OK) {
                    break;
                }
                if (len) {
                    status = JSONAppendChar(json, ',');
                    if (status != DPS_OK) {
                        break;
                    }
                }
            }
            if (status == DPS_OK) {
                status = Indent(json, pretty, indent);
            }
            if (status == DPS_OK) {
                status = JSONAppendChar(json, ']');
            }
        }
        break;
    case CBOR_MAP:
        status = CBOR_DecodeMap(cbor, &len);
        if (status == DPS_OK) {
            status = JSONAppendChar(json, '{');
        }
        if (status == DPS_OK) {
            while (len--) {
                status = ToJSON(json, cbor, pretty, indent + 1);
                if (status == DPS_OK) {
                    status = JSONAppendChar(json, ':');
                }
                if (status != DPS_OK) {
                    break;
                }
                status = ToJSON(json, cbor, pretty, indent + 1);
                if (status != DPS_OK) {
                    break;
                }
                if (len) {
                    status = JSONAppendChar(json, ',');
                    if (status != DPS_OK) {
                        break;
                    }
                }
            }
            if (status == DPS_OK) {
                status = Indent(json, pretty, indent);
            }
            if (status == DPS_OK) {
                status = JSONAppendChar(json, '}');
            }
        }
        break;
    case CBOR_OTHER:
        if (cbor->rxPos[0] == CBOR_TRUE) {
            CBOR_Skip(cbor, NULL, NULL);
            status = JSONAppendStr(json, "true");
            break;
        }
        if (cbor->rxPos[0] == CBOR_FALSE) {
            CBOR_Skip(cbor, NULL, NULL);
            status = JSONAppendStr(json, "false");
            break;
        }
        if (cbor->rxPos[0] == CBOR_NULL) {
            CBOR_Skip(cbor, NULL, NULL);
            status = JSONAppendStr(json, "null");
            break;
        }
        if (cbor->rxPos[0] == CBOR_FLOAT || cbor->rxPos[0] == CBOR_DOUBLE) {
            double d;
            status = CBOR_DecodeDouble(cbor, &d);
            if (status == DPS_OK) {
                size = snprintf(json->str, json->len, "%f", d);
                if (size >= json->len) {
                    status = DPS_ERR_OVERFLOW;
                } else {
                    json->len -= size;
                    json->str += size;
                }
            }
            break;
        }
        status = DPS_ERR_INVALID;
        break;
    default:
        DPS_ERRPRINT("Invalid CBOR major %02x\n", maj);
        status = DPS_ERR_INVALID;
    }
    return status;
}

DPS_Status DPS_CBOR2JSON(const uint8_t* cbor, size_t cborLen, char* json, size_t jsonSize, int pretty)
{
    int indent = 0;
    DPS_Status status;
    DPS_RxBuffer rxBuf;
    JSONBuffer jsonBuf;

    DPS_DBGTRACEA("cbor=%p,cborLen=%d,json=%p,jsonSize=%d,pretty=%d\n",
                  cbor, cborLen, json, jsonSize, pretty);

    if (!json || !cbor) {
        return DPS_ERR_NULL;
    }
    if (jsonSize == 0) {
        return DPS_ERR_OVERFLOW;
    }
    // Empty CBOR is ok
    if (cborLen == 0) {
        json[0] = '\0';
        return DPS_OK;
    }
    DPS_RxBufferInit(&rxBuf, (uint8_t*)cbor, cborLen);
    jsonBuf.str = json;
    jsonBuf.len = jsonSize;
    status = ToJSON(&jsonBuf, &rxBuf, pretty, indent);
    if (status == DPS_ERR_OVERFLOW) {
        DPS_WARNPRINT("JSON buffer too small\n");
    } else if (status != DPS_OK) {
        DPS_ERRPRINT("Invalid CBOR at offset %d\n", (int)(rxBuf.rxPos - rxBuf.base));
    }
    return status;
}
