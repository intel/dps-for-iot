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
#include "cbor.h"

static uint8_t buf[10000];

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
    { 1, "a"}, { 2, "bc"}, {3, "def"}
};

int main(int argc, char** argv)
{
    size_t i;
    size_t n;
    DPS_TxBuffer txBuffer;
    DPS_RxBuffer rxBuffer;
    uint8_t* test;
    size_t size;

    DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));

    /*
     * Encode same values twice
     */
    for (n = 0; n < 2; ++n) {

        CBOR_EncodeArray(&txBuffer, 40);

        for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
            CBOR_EncodeUint(&txBuffer, Uints[i]);
        }

        CBOR_EncodeBytes(&txBuffer, (uint8_t*)Uints, sizeof(Uints));

        for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
            CBOR_EncodeInt(&txBuffer, Sints[i]);
        }

        CBOR_EncodeArray(&txBuffer, sizeof(Strings) / sizeof(Strings[0]));

        for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
            CBOR_EncodeString(&txBuffer, Strings[i]);
        }

        CBOR_EncodeMap(&txBuffer, sizeof(Maps) / sizeof(Maps[0]));

        for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
            CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CBOR_EncodeString(&txBuffer, Maps[i].string);
        }

        for (i = 0; i < sizeof(Tags) / sizeof(Tags[0]); ++i) {
            CBOR_EncodeTag(&txBuffer, Tags[i]);
        }
    }

    printf("Encoded %zu bytes\n", DPS_TxBufferUsed(&txBuffer));

    CBOR_Dump(NULL, txBuffer.base, DPS_TxBufferUsed(&txBuffer));

    DPS_TxBufferToRx(&txBuffer, &rxBuffer);

    CBOR_DecodeArray(&rxBuffer, &size);
    assert(size == 40);

    /*
     * Decode
     */
    for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
        uint64_t n;
        CBOR_DecodeUint(&rxBuffer, &n);
        assert(n == Uints[i]);
    }

    CBOR_DecodeBytes(&rxBuffer, &test, &i);
    assert(i == sizeof(Uints));
    assert(memcmp(Uints, test, i) == 0);

    for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
        int64_t n;
        CBOR_DecodeInt(&rxBuffer, &n);
        assert(n == Sints[i]);
    }

    CBOR_DecodeArray(&rxBuffer, &size);
    assert(size == (sizeof(Strings) / sizeof(Strings[0])));

    for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
        char *str;
        size_t len;
        CBOR_DecodeString(&rxBuffer, &str, &len);
        assert(!strcmp(str, Strings[i]));
    }

    CBOR_DecodeMap(&rxBuffer, &size);
    assert(size == (sizeof(Maps) / sizeof(Maps[0])));

    for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
        char *str;
        uint64_t n;
        size_t len;
        CBOR_DecodeUint(&rxBuffer, &n);
        assert(n == Maps[i].key);
        CBOR_DecodeString(&rxBuffer, &str, &len);
        assert(!strcmp(str, Maps[i].string));
    }

    for (i = 0; i < sizeof(Tags) / sizeof(Tags[0]); ++i) {
        int64_t n;
        CBOR_DecodeTag(&rxBuffer, &n);
        assert(n == Tags[i]);
    }

    /*
     * Skip
     */
    CBOR_DecodeArray(&rxBuffer, &size);
    assert(size == 40);

    for (n = 0; n < 40; ++n) {
        size_t sz;
        uint8_t maj;
        DPS_Status ret = CBOR_Skip(&rxBuffer, &maj, &sz);
        if (ret != DPS_OK) {
            printf("Failed\n");
            exit(1);
        }
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
        printf("Failed\n");
        exit(1);
    }

    /*
     * Test wrap bytes with various hint lengths from 1 byte to 8
     */
    for (i = 5; i < 63; ++i) {
        DPS_RxBuffer rxInner;
        char* str;
        static const char testString[] = "Test string";
        uint8_t* data;
        uint8_t* wrapPtr;

        DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
        CBOR_StartWrapBytes(&txBuffer, 1ull << i, &wrapPtr);
        CBOR_EncodeString(&txBuffer, testString);
        CBOR_EndWrapBytes(&txBuffer, wrapPtr);

        DPS_TxBufferToRx(&txBuffer, &rxBuffer);

        CBOR_DecodeBytes(&rxBuffer, &data, &size);
        assert(!DPS_RxBufferAvail(&rxBuffer));

        DPS_RxBufferInit(&rxInner, data, size);
        CBOR_DecodeString(&rxInner, &str, &size);
        assert(!DPS_RxBufferAvail(&rxInner));

        assert(strcmp(str, testString) == 0);
    }

    printf("Passed\n");
}
