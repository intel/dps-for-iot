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

#include "test.h"
#include "float.h"
#include "math.h"

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

static const float Floats[] = {
    100000.0, 3.4028234663852886e+38, INFINITY, NAN, -INFINITY
};

static const double Doubles[] = {
    1.1, 1.0e+300, -4.1, INFINITY, NAN, -INFINITY
};

static const double DoublesAsFloat[] = {
    0.0, -FLT_MAX, FLT_MAX, (double)FLT_MAX * 1.0000000000000002, 12345.67890123
};

// Surprisingly INT32_MIN can be represented exactly as a float!
static const int64_t IntsAsFloat[] = {
    0, 202, -202, -16777216ll, 16777216ll, -16777217ll, 16777217ll, INT32_MAX, INT32_MIN + 1
};

// Surprisingly INT64_MIN can be represented exactly as a double!
static const int64_t IntsAsDouble[] = {
    0, 2, -3, -9007199254740992ll, 9007199254740992ll, INT32_MAX, INT32_MIN, -9007199254740993ll, 9007199254740993ll, INT64_MAX, INT64_MIN + 1
};

static DPS_Status TestFloatingPoint()
{
    DPS_TxBuffer txBuffer;
    size_t i;
    DPS_Status ret;

    for (i = 0; i < A_SIZEOF(Floats); ++i) {
        DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
        ret = CBOR_EncodeFloat(&txBuffer, Floats[i]);
        if (ret != DPS_OK) {
            return ret;
        }
        CBOR_Dump(NULL, txBuffer.base, DPS_TxBufferUsed(&txBuffer));
    }

    for (i = 0; i < A_SIZEOF(Doubles); ++i) {
        DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
        ret = CBOR_EncodeDouble(&txBuffer, Doubles[i]);
        if (ret != DPS_OK) {
            return ret;
        }
        CBOR_Dump(NULL, txBuffer.base, DPS_TxBufferUsed(&txBuffer));
    }
    return DPS_OK;
}

static DPS_Status TestTextString()
{
    DPS_TxBuffer txBuffer;
    DPS_RxBuffer rxBuffer;
    size_t i;
    DPS_Status ret;
    char* str;
    size_t len;

    const uint8_t empty[] = { 0x60 };
    const uint8_t a[] = { 0x61, 0x61 };
    const uint8_t IETF[] = { 0x64, 0x49, 0x45, 0x54, 0x46 };
    const uint8_t quote[] = { 0x62, 0x22, 0x5c };
    const uint8_t _00fc[] = { 0x62, 0xc3, 0xbc };
    const struct {
        const char* s;
        const uint8_t* b;
        size_t nb;
    } examples[] = {
        { "", empty, A_SIZEOF(empty) },
        { "a", a, A_SIZEOF(a) },
        { "IETF", IETF, A_SIZEOF(IETF) },
        { "\"\\", quote, A_SIZEOF(quote) },
#if __STDC_VERSION__ >= 199901L
        { "\u00fc", _00fc, A_SIZEOF(_00fc) }
#endif
    };

    for (i = 0; i < A_SIZEOF(examples); ++i) {
        DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
        ret = CBOR_EncodeString(&txBuffer, examples[i].s);
        CHECK(ret);
        ASSERT(examples[i].nb == DPS_TxBufferUsed(&txBuffer));
        ASSERT(memcmp(examples[i].b, txBuffer.base, DPS_TxBufferUsed(&txBuffer)) == 0);

        DPS_TxBufferToRx(&txBuffer, &rxBuffer);
        ret = CBOR_DecodeString(&rxBuffer, &str, &len);
        ASSERT(strlen(examples[i].s) == len);
        ASSERT((len == 0) || (strncmp(examples[i].s, str, len) == 0));
    }

    /*
     * bigString is explicitly not NUL terminated in order to ensure
     * that OVERFLOW is correctly returned for CBOR_EncodeString and
     * that a NUL terminator is not required for
     * CBOR_EncodeStringAndLength.
     */
    char bigString[CBOR_MAX_STRING_LEN * 2];
    memset(bigString, 'A', CBOR_MAX_STRING_LEN * 2);
    DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
    ret = CBOR_EncodeString(&txBuffer, bigString);
    ASSERT(ret == DPS_ERR_OVERFLOW);
    DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));
    ret = CBOR_EncodeStringAndLength(&txBuffer, bigString, CBOR_MAX_STRING_LEN * 2);
    ASSERT(ret == DPS_OK);

    return DPS_OK;

Failed:
    printf("Failed at line %d %s\n", ln, DPS_ErrTxt(ret));
    return ret;
}

#define NUM_ENCODED_VALS   84

int main(int argc, char** argv)
{
    size_t i;
    size_t n;
    DPS_Status ret;
    DPS_TxBuffer txBuffer;
    DPS_RxBuffer rxBuffer;
    uint8_t* test;
    size_t size;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    ret = TestFloatingPoint();
    CHECK(ret);
    ret = TestTextString();
    CHECK(ret);

    DPS_TxBufferInit(&txBuffer, buf, sizeof(buf));

    /*
     * Encode same values twice - one to test decode, one to test skip
     */
    for (n = 0; n < 2; ++n) {

        ret = CBOR_EncodeArray(&txBuffer, NUM_ENCODED_VALS);
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
        for (i = 0; i < sizeof(Floats) / sizeof(Floats[0]); ++i) {
            ret = CBOR_EncodeFloat(&txBuffer, Floats[i]);
            CHECK(ret);
        }
        for (i = 0; i < sizeof(Doubles) / sizeof(Doubles[0]); ++i) {
            ret = CBOR_EncodeDouble(&txBuffer, Doubles[i]);
            CHECK(ret);
        }
        for (i = 0; i < sizeof(DoublesAsFloat) / sizeof(DoublesAsFloat[0]); ++i) {
            ret = CBOR_EncodeDouble(&txBuffer, DoublesAsFloat[i]);
            CHECK(ret);
        }
        for (i = 0; i < sizeof(IntsAsDouble) / sizeof(IntsAsDouble[0]); ++i) {
            ret = CBOR_EncodeInt(&txBuffer, IntsAsDouble[i]);
            CHECK(ret);
        }
        for (i = 0; i < sizeof(IntsAsFloat) / sizeof(IntsAsFloat[0]); ++i) {
            ret = CBOR_EncodeInt(&txBuffer, IntsAsFloat[i]);
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

        ret = CBOR_EncodeMap(&txBuffer, 0); /* { } */
        CHECK(ret);
        ret = CBOR_EncodeMap(&txBuffer, 0); /* { } */
        CHECK(ret);
        ret = CBOR_EncodeMap(&txBuffer, 3); /* { need, want, ignore } */
        CHECK(ret);
        for (i = 0; i < 3; ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, 1); /* { need } */
        CHECK(ret);
        for (i = 0; i < 1; ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, 1); /* { want } */
        CHECK(ret);
        for (i = 0; i < 1; ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, 1); /* { need } */
        CHECK(ret);
        for (i = 0; i < 1; ++i) {
            ret = CBOR_EncodeInt(&txBuffer, Maps[i].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[i].string);
            CHECK(ret);
        }
        ret = CBOR_EncodeMap(&txBuffer, 2); /* { >need, need } */
        CHECK(ret);
        for (i = 0; i < 2; ++i) {
            size_t j = A_SIZEOF(Maps) - 1 - i;
            ret = CBOR_EncodeInt(&txBuffer, Maps[j].key);
            CHECK(ret);
            ret = CBOR_EncodeString(&txBuffer, Maps[j].string);
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
    ASSERT(size == NUM_ENCODED_VALS);
    CHECK(ret);

    /*
     * Decode
     */
    for (i = 0; i < sizeof(Uints) / sizeof(Uints[0]); ++i) {
        uint64_t n;
        ret = CBOR_DecodeUint(&rxBuffer, &n);
        ASSERT(n == Uints[i]);
        CHECK(ret);
    }

    CBOR_DecodeBytes(&rxBuffer, &test, &i);
    ASSERT(i == sizeof(Uints));
    ASSERT(memcmp(Uints, test, i) == 0);

    for (i = 0; i < sizeof(Sints) / sizeof(Sints[0]); ++i) {
        int64_t n;
        ret = CBOR_DecodeInt(&rxBuffer, &n);
        ASSERT(n == Sints[i]);
        CHECK(ret);
    }

    for (i = 0; i < sizeof(Floats) / sizeof(Floats[0]); ++i) {
        float f;
        ret = CBOR_DecodeFloat(&rxBuffer, &f);
        ASSERT((f == Floats[i]) || (isnan(f) && isnan(Floats[i])));
        CHECK(ret);
    }

    for (i = 0; i < sizeof(Doubles) / sizeof(Doubles[0]); ++i) {
        double d;
        ret = CBOR_DecodeDouble(&rxBuffer, &d);
        ASSERT((d == Doubles[i]) || (isnan(d) && isnan(Doubles[i])));
        CHECK(ret);
    }
    // These are doubles on the wire
    for (i = 0; i < sizeof(DoublesAsFloat) / sizeof(DoublesAsFloat[0]); ++i) {
        float f;
        ret = CBOR_DecodeFloat(&rxBuffer, &f);
        switch (i) {
        case 3:
            if (ret == DPS_ERR_RANGE) {
                printf("Decode %f failed as expected %s\n", DoublesAsFloat[i], DPS_ErrTxt(ret));
                ret = DPS_OK;
            } else {
                printf("Decode %f did not fail as expected\n", DoublesAsFloat[i]);
                ret = DPS_ERR_INVALID;
            }
            break;
        case 4:
            if (ret == DPS_ERR_LOST_PRECISION) {
                printf("Decode %f failed as expected %s\n", DoublesAsFloat[i], DPS_ErrTxt(ret));
                ret = DPS_OK;
            } else {
                printf("Decode %f did not fail as expected\n", DoublesAsFloat[i]);
                ret = DPS_ERR_INVALID;
            }
            break;
        default:
            ASSERT(f == (float)DoublesAsFloat[i]);
        }
        CHECK(ret);
    }
    // These are integers on the wire - decode as doubles
    for (i = 0; i < sizeof(IntsAsDouble) / sizeof(IntsAsDouble[0]); ++i) {
        double d;
        ret = CBOR_DecodeDouble(&rxBuffer, &d);
        switch (i) {
        case 7:
        case 8:
        case 9:
        case 10:
            if (ret == DPS_ERR_LOST_PRECISION) {
                printf("Decode %zi failed as expected %s\n", IntsAsDouble[i], DPS_ErrTxt(ret));
                ret = DPS_OK;
            } else {
                printf("Decode %zi did not fail as expected\n", IntsAsDouble[i]);
                ret = DPS_ERR_INVALID;
            }
            break;
        default:
            ASSERT(d == (double)IntsAsDouble[i]);
        }
        CHECK(ret);
    }
    // These are integers on the wire - decode as floats
    for (i = 0; i < sizeof(IntsAsFloat) / sizeof(IntsAsFloat[0]); ++i) {
        float f;
        ret = CBOR_DecodeFloat(&rxBuffer, &f);
        switch (i) {
        case 5:
        case 6:
        case 7:
        case 8:
            if (ret == DPS_ERR_LOST_PRECISION) {
                printf("Decode %zi failed as expected %s\n", IntsAsFloat[i], DPS_ErrTxt(ret));
                ret = DPS_OK;
            } else {
                printf("Decode %zi did not fail as expected\n", IntsAsFloat[i]);
                ret = DPS_ERR_INVALID;
            }
            break;
        default:
            ASSERT(f == (float)IntsAsFloat[i]);
        }
        CHECK(ret);
    }

    ret = CBOR_DecodeArray(&rxBuffer, &size);
    ASSERT(size == (sizeof(Strings) / sizeof(Strings[0])));
    CHECK(ret);

    for (i = 0; i < sizeof(Strings) / sizeof(Strings[0]); ++i) {
        char *str;
        size_t len;
        ret = CBOR_DecodeString(&rxBuffer, &str, &len);
        ASSERT(strlen(Strings[i]) == len && !strncmp(str, Strings[i], len));
        CHECK(ret);
    }

    ret = CBOR_DecodeMap(&rxBuffer, &size);
    ASSERT(size == (sizeof(Maps) / sizeof(Maps[0])));
    CHECK(ret);

    for (i = 0; i < sizeof(Maps) / sizeof(Maps[0]); ++i) {
        char *str;
        uint64_t n;
        size_t len;
        ret = CBOR_DecodeUint(&rxBuffer, &n);
        CHECK(ret);
        ASSERT(n == Maps[i].key);
        ret = CBOR_DecodeString(&rxBuffer, &str, &len);
        CHECK(ret);
        ASSERT(strlen(Maps[i].string) == len && !strncmp(str, Maps[i].string, len));
    }

    {
        /* { } */
        CBOR_MapState map;
        ret = DPS_ParseMapInit(&map, &rxBuffer, NULL, 0, NULL, 0);
        CHECK(ret);
        if (!DPS_ParseMapDone(&map)) {
            CHECK(DPS_ERR_FAILURE);
        }
    }
    {
        /* { } - XFAIL missing needed key */
        CBOR_MapState map;
        int32_t needs[] = { 1 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, needs, A_SIZEOF(needs), NULL, 0);
        CHECK(ret);
        if (DPS_ParseMapDone(&map)) {
            CHECK(DPS_ERR_FAILURE);
        }
        int32_t key = 0;
        ret = DPS_ParseMapNext(&map, &key);
        if (ret != DPS_ERR_MISSING) {
            CHECK(DPS_ERR_FAILURE);
        }
    }
    {
        /* { need, want, ignore } */
        CBOR_MapState map;
        int32_t needs[] = { 1 };
        int32_t wants[] = { 2 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, needs, A_SIZEOF(needs), wants, A_SIZEOF(wants));
        CHECK(ret);
        while (!DPS_ParseMapDone(&map)) {
            int32_t key = 0;
            char *str;
            size_t len;
            ret = DPS_ParseMapNext(&map, &key);
            CHECK(ret);
            switch (key) {
            case 1:
            case 2:
                ret = CBOR_DecodeString(&rxBuffer, &str, &len);
                CHECK(ret);
                break;
            default:
                ASSERT(0);
                break;
            }
        }
    }
    {
        /* { need } - XFAIL missing needed key */
        CBOR_MapState map;
        int32_t needs[] = { 2 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, needs, A_SIZEOF(needs), NULL, 0);
        CHECK(ret);
        if (DPS_ParseMapDone(&map)) {
            CHECK(DPS_ERR_FAILURE);
        }
        int32_t key = 0;
        ret = DPS_ParseMapNext(&map, &key);
        if (ret != DPS_ERR_MISSING) {
            CHECK(DPS_ERR_FAILURE);
        }
    }
    {
        /* { want } - PASS missing wanted key */
        CBOR_MapState map;
        int32_t wants[] = { 2 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, NULL, 0, wants, A_SIZEOF(wants));
        CHECK(ret);
        while (!DPS_ParseMapDone(&map)) {
            int32_t key = 0;
            ret = DPS_ParseMapNext(&map, &key);
            CHECK(ret);
            if (key != 0) {
                CHECK(DPS_ERR_FAILURE);
            }
        }
    }
    {
        /* { need } */
        CBOR_MapState map;
        int32_t needs[] = { 1 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, needs, A_SIZEOF(needs), NULL, 0);
        CHECK(ret);
        while (!DPS_ParseMapDone(&map)) {
            int32_t key = 0;
            char *str;
            size_t len;
            ret = DPS_ParseMapNext(&map, &key);
            CHECK(ret);
            switch (key) {
            case 1:
                ret = CBOR_DecodeString(&rxBuffer, &str, &len);
                CHECK(ret);
                break;
            default:
                ASSERT(0);
                break;
            }
        }
    }
    {
        /* { >need, need } - XFAIL keys out of order */
        CBOR_MapState map;
        int32_t needs[] = { 3 };
        ret = DPS_ParseMapInit(&map, &rxBuffer, needs, A_SIZEOF(needs), NULL, 0);
        CHECK(ret);
        if (DPS_ParseMapDone(&map)) {
            CHECK(DPS_ERR_FAILURE);
        }
        int32_t key = 0;
        ret = DPS_ParseMapNext(&map, &key);
        if (ret != DPS_ERR_MISSING) {
            CHECK(DPS_ERR_FAILURE);
        }
        ret = CBOR_Skip(&rxBuffer, NULL, NULL); /* "ghi" */
        CHECK(ret);
        ret = CBOR_Skip(&rxBuffer, NULL, NULL); /* 3 */
        CHECK(ret);
        ret = CBOR_Skip(&rxBuffer, NULL, NULL); /* "def" */
        CHECK(ret);
    }

    CBOR_MapState map;
    int32_t keys[] = {2, 3};
    ret = DPS_ParseMapInit(&map, &rxBuffer, keys, A_SIZEOF(keys), NULL, 0);
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
            ASSERT(0);
            break;
        }
    }

    for (i = 0; i < sizeof(Tags) / sizeof(Tags[0]); ++i) {
        uint64_t n;
        ret = CBOR_DecodeTag(&rxBuffer, &n);
        ASSERT(n == Tags[i]);
        CHECK(ret);
    }

    /*
     * Skip
     */
    ret = CBOR_DecodeArray(&rxBuffer, &size);
    CHECK(ret);
    ASSERT(size == NUM_ENCODED_VALS);

    for (n = 0; n < NUM_ENCODED_VALS; ++n) {
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
        ASSERT(!DPS_RxBufferAvail(&rxBuffer));
        CHECK(ret);
        DPS_RxBufferInit(&rxInner, data, size);
        ret = CBOR_DecodeString(&rxInner, &str, &size);
        ASSERT(!DPS_RxBufferAvail(&rxInner));
        ASSERT(strlen(testString) == size && strncmp(str, testString, size) == 0);
        CHECK(ret);
    }

    printf("Passed\n");
    return EXIT_SUCCESS;

Failed:

    printf("Failed at line %d %s\n", ln, DPS_ErrTxt(ret));
    return EXIT_FAILURE;
}
