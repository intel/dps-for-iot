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

#include "test.h"
#include <dps/json.h>

static int ln;

#define CHECK(r)   if ((r) != DPS_OK) { status = (r); ln = __LINE__; goto Failed; }

static const char json0[] = "1234";
static const char json1[] = "-0.5";
static const char json2[] = "[]";
static const char json3[] = "[1.0]";
static const char json4[] = "{}";
static const char json5[] = "{\"x\":2}";
static const char json6[] = "true";
static const char json7[] = "\"hello world\"";
static const char json8[] = "[1,-1, 2.0, +3.5 ,   -4.0    , -555555  ,6,7,-8,+9]";
static const char json9[] = "{ \"red\":1, \"green\" : 2, \"blue\": 3 }";
static const char json10[] =
"[                      \
    [1,2,3,4],          \
    [],                 \
    [1],                \
    [true,false],       \
    \"string\",         \
    [null,0,\"zilch\"], \
    [\"a\",\"b\",\"c\"] \
 ]";
static const char json11[] =
"{                            \
   \"true\" : true,           \
   \"array1\": [4  , 5],      \
   \"false\" : false,         \
   \"array2\":[ 1, 2,3, 4, 5], \
   \"map1\": {                \
                \"map2\":{\"1\":1,\"3\":2}\
             },               \
   \"null\":null              \
 }";
static const char json12[] =
"[           \
    { \"$binary\":\"abcdef0123456789\" }, \
    { \"$binary\" :\"AaBbCcDdEdFf\" }, \
    { \"$binary\":   \"00\" }, \
    { \"$binary\":\"\" } \
 ]";
static const char json13[] = "1";
static const char json14[] = "";

static const char* tests[] = {
    json0, json1, json2, json3, json4, json5, json6, json7, json8, json9, json10, json11, json12, json13, json14
};

static const char bad0[] = "abcd";
static const char bad1[] = "[ 1,2,3,4,5";
static const char bad2[] = "{ \"foo\":4 ]";
static const char bad3[] = "[ 1 2 3 4 ]";
static const char bad4[] = "{ a:b, c:d }";
static const char bad5[] = "[[[[ 1, 2 ], 3]}]";
static const char bad6[] = "ab\ncd";
static const char bad7[] = "] 1,2 [";
static const char bad8[] = "[ 1,2,+,= ]";
static const char bad9[] = "]";
static const char bad10[] = "[";
static const char bad11[] = "{";
static const char bad12[] = "}";
static const char bad13[] = "*";
static const char bad14[] = "tru";
static const char bad15[] = "falsed";


static const char* invalid[] = {
    bad0, bad1, bad2, bad3, bad4, bad5, bad6, bad7, bad8, bad9, bad10, bad11, bad12, bad13, bad14, bad15
};

static uint8_t cbor1[1024];
static uint8_t cbor2[1024];
static char json[4096];

int main(int argc, char** argv)
{
    DPS_Status status = DPS_OK;
    int pretty;
    size_t cbor1Len;
    size_t cbor2Len;
    int i;
    // Check with and without formatting
    for (pretty = 0; pretty <= 1; ++pretty) {
        for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); ++i) {
            // Encode as CBOR
            status = DPS_JSON2CBOR(tests[i], cbor1, sizeof(cbor1), &cbor1Len);
            CHECK(status);
            // Decode to JSON
            status = DPS_CBOR2JSON(cbor1, cbor1Len, json, sizeof(json), pretty);
            CHECK(status);
            printf("%s\n", json);
            // Encode again as CBOR
            status = DPS_JSON2CBOR(json, cbor2, sizeof(cbor2), &cbor2Len);
            CHECK(status);
            // Fidelity check that two CBOR encodings are the same
            if (cbor1Len != cbor2Len) {
                printf("Test %d failed: CBOR lengths %zu != %zu\n", i, cbor1Len, cbor2Len);
                CHECK(DPS_ERR_FAILURE);
            }
            if (memcmp(cbor1, cbor2, cbor1Len) != 0) {
                printf("Test %d failed: CBOR encodings are different:\n%s\n\n%s\n\n", i, tests[i], json);
                CHECK(DPS_ERR_FAILURE);
            }
        }
    }
    // These should all fail
    for (i = 0; i < (sizeof(invalid) / sizeof(invalid[0])); ++i) {
        size_t cbor1Len;
        // Encode as CBOR
        status = DPS_JSON2CBOR(invalid[i], cbor1, sizeof(cbor1), &cbor1Len);
        if (status == DPS_OK) {
            printf("Test of invalid input %d failed\n\n", i);
            CHECK(DPS_ERR_FAILURE);
        }
    }
    // Test buffer overflow checks
    for (pretty = 0; pretty <= 1; ++pretty) {
        for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); ++i) {
            status = DPS_JSON2CBOR(tests[i], cbor1, sizeof(cbor1), &cbor1Len);
            CHECK(status);
            if (cbor1Len != 0) {
                // This should fail
                status = DPS_JSON2CBOR(tests[i], cbor2, cbor1Len - 1, &cbor2Len);
                if (status != DPS_ERR_OVERFLOW) {
                    printf("Test for CBOR overrun %d failed\n\n", i);
                    CHECK(DPS_ERR_FAILURE);
                }
                status = DPS_CBOR2JSON(cbor1, cbor1Len, json, sizeof(json), pretty);
                CHECK(status);
                // This should fail
                status = DPS_CBOR2JSON(cbor1, cbor1Len, json, strlen(json) - 1, pretty);
                if (status != DPS_ERR_OVERFLOW) {
                    printf("Test for JSON overrun %d failed\n\n", i);
                    CHECK(DPS_ERR_FAILURE);
                }
            }
        }
    }

    printf("Passed\n");
    return EXIT_SUCCESS;

Failed:

    printf("Failed at test %d line %d %s\n", i, ln, DPS_ErrTxt(status));
    return EXIT_FAILURE;
}
