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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dps/private/cbor.h>

static uint8_t buf[1 << 19];

typedef struct _map {
    int key;
    char *string;
}map;

static uint64_t Tags[] = {
    993, 996, 997, 998, 999
};

static uint64_t Uints[] = {
    0, 1, 2, 3, 23, 24, 254, 255, 256, 65534, 65536, 65537,
    UINT32_MAX - 1, UINT32_MAX, (uint64_t)UINT32_MAX + 1,
    UINT64_MAX - 1, UINT64_MAX
};

static uint64_t Sints[] = {
    INT64_MIN, INT64_MIN + 1,
    -1, 0, 1, -22, -23, -24, -25, -254, -255, -256, -257,
    INT64_MAX - 1, INT64_MAX

};

static const char *Strings[] = {
    "a", "bc", "def"
};

static const map Maps[] = {
    {1, "a"}, {2, "bc"}, {3, "def"}, {4, "ghi"}
};

static int ln;

#define CHECK(r)   if ((r) != DPS_OK) { ln = __LINE__; goto Failed; }

int main(int argc, char** argv)
{
    size_t i;
    size_t n;
    DPS_Status ret;
    DPS_TxBuffer txBuffer;
    DPS_RxBuffer rxBuffer;
    uint8_t* test;
    size_t size;

    DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));

    /*
     * Encode same values twice
     */
    for (n = 0; n < 2; ++n) {

        ret = CBOR_EncodeArray(&txBuffer, 41);
        CHECK(ret);

        for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
            ret = CBOR_EncodeUint(&txBuffer, Uints[i]);
            CHECK(ret);
        }
        ret = CBOR_EncodeBytes(&txBuffer, (uint8_t*)Uints, sizeof(Uints));
        CHECK(ret);
        for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Sints[i]);
            CHECK(ret);
        }
        ret = CBOR_EncodeArray(&txBuffer, sizeof(Strings) / sizeof(Strings[0]));
        CHECK(ret);
        for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
            ret = CBOR_EncodeString(&txBuffer, Strings[i]);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, sizeof(Maps) / sizeof(Maps[0]));
        CHECK(ret);
        for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, sizeof(Maps) / sizeof(Maps[0]));
        CHECK(ret);
        for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        for (i = 0; i < sizeof(Tags) / sizeof(Tags[0]); ++i) {
            ret = CBOR_EncodeTag(&txBuffer, Tags[i]);
            CHECK(ret);
        }
    }

    printf("Encoded %u bytes\n", DPS_TxBufferUsed(&txBuffer));

    CBOR_Dump(NULL, txBuffer.base, DPS_TxBufferUsed(&txBuffer));

    DPS_TxBufferToRx(&txBuffer, &rxBuffer);

    ret = CBOR_DecodeArray(&rxBuffer, &size);
    assert(size == 41);
    CHECK(ret);

    /*
     * Decode
     */
    for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
        uint64_t n;
        ret = CBOR_DecodeUint(&rxBuffer, &n);
        assert(n == Uints[i]);
        CHECK(ret);
    }

    CBOR_DecodeBytes(&rxBuffer, &test, &i);
    assert(i == sizeof(Uints));
    assert(memcmp(Uints, test, i) == 0);

    for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
        int64_t n;
        ret = CBOR_DecodeInt(&rxBuffer, &n);
        assert(n == Sints[i]);
        CHECK(ret);
    }

    ret = CBOR_DecodeArray(&rxBuffer, &size);
    assert(size == (sizeof(Strings) / sizeof(Strings[0])));
    CHECK(ret);

    for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
        char *str;
        size_t len;
        ret = CBOR_DecodeString(&rxBuffer, &str, &len);
        assert(!strcmp(str, Strings[i]));
        CHECK(ret);
    }

    ret = CBOR_DecodeMap(&rxBuffer, &size);
    assert(size == (sizeof(Maps) / sizeof(Maps[0])));
    CHECK(ret);

    for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
        char *str;
        uint64_t n;
        size_t len;
        ret = CBOR_DecodeUint(&rxBuffer, &n);
        CHECK(ret);
        assert(n == Maps[i].key);
        ret = CBOR_DecodeString(&rxBuffer, &str, &len);
        CHECK(ret);
        assert(!strcmp(str, Maps[i].string));
    }

    CBOR_MapState map;
    int32_t keys[] = {2, 3};
    ret = DPS_ParseMapInit(&map, &rxBuffer, keys, A_SIZEOF(keys));
    CHECK(ret);

    while (!DPS_ParseMapDone(&map)) {
        int32_t key = 0;
        char *str;
        size_t len;
        ret = DPS_ParseMapNext(&map, &key);
        CHECK(ret);
        switch (key) {
        case 2:
        case 3:
            ret = CBOR_DecodeString(&rxBuffer, &str, &len);
            CHECK(ret);
            break;
        default:
            assert(0);
            break;
        }
    }

    for (i = 0; i < sizeof(Tags) / sizeof(Tags[0]); ++i) {
        int64_t n;
        ret = CBOR_DecodeTag(&rxBuffer, &n);
        assert(n == Tags[i]);
        CHECK(ret);
    }

    /*
     * Skip
     */
    ret = CBOR_DecodeArray(&rxBuffer, &size);
    CHECK(ret);
    assert(size == 41);

    for (n = 0; n < 41; ++n) {
        size_t sz;
        uint8_t maj;
        ret = CBOR_Skip(&rxBuffer, &maj, &sz);
        CHECK(ret);
        switch (maj) {
        case CBOR_UINT:
            printf("Skipped UINT size %zu\n", sz);
            break;
        case CBOR_NEG:
            printf("Skipped NEG size %zu\n", sz);
            break;
        case CBOR_BYTES:
            printf("Skipped Bytes size %zu\n", sz);
            break;
        case CBOR_STRING:
            printf("Skipped String size %zu\n", sz);
            break;
        case CBOR_ARRAY:
            printf("Skipped Array size %zu\n", sz);
            break;
        case CBOR_MAP:
            printf("Skipped Map size %zu\n", sz);
            break;
        case CBOR_TAG:
            printf("Skipped Tag size %zu\n", sz);
            break;
        case CBOR_OTHER:
            printf("Skipped Other size %zu\n", sz);
            break;
        }
    }

    if (DPS_RxBufferAvail(&rxBuffer)) {
        CHECK(DPS_ERR_INVALID);
    }

    /*
     * Test wrap bytes with various hint lengths from 1 byte to 4
     */
    for (i = 5; i < 18; ++i) {
        DPS_RxBuffer rxInner;
        char* str;
        static const char testString[] = "Test string";
        uint8_t* data;
        uint8_t* wrapPtr;

        DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
        ret = CBOR_StartWrapBytes(&txBuffer, 1ull << i, &wrapPtr);
        CHECK(ret);
        ret = CBOR_EncodeString(&txBuffer, testString);
        CHECK(ret);
        ret = CBOR_EndWrapBytes(&txBuffer, wrapPtr);
        CHECK(ret);
        DPS_TxBufferToRx(&txBuffer, &rxBuffer);
        ret = CBOR_DecodeBytes(&rxBuffer, &data, &size);
        assert(!DPS_RxBufferAvail(&rxBuffer));
        CHECK(ret);
        DPS_RxBufferInit(&rxInner, data, size);
        ret = CBOR_DecodeString(&rxInner, &str, &size);
        assert(!DPS_RxBufferAvail(&rxInner));
        assert(strcmp(str, testString) == 0);
        CHECK(ret);
    }

    printf("Passed\n");
    return 0;

Failed:

    printf("Failed at line %d %s\n", ln, DPS_ErrTxt(ret));
    return 1;
}
