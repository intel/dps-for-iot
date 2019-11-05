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

static int ln;

#define CHECK(r)   if ((r) != DPS_OK) { ln = __LINE__; goto Failed; }

/*
 * UUID bytes are in little-endian order
 */
static DPS_UUID a = { 0x1a, 0x2c, 0xba, 0xd4, 0xa0, 0xee, 0x52, 0xe2,
                      0xe8, 0xa1, 0x29, 0x36, 0xe8, 0x10, 0x27, 0x53 };
static DPS_UUID b = { 0x02, 0xf8, 0x40, 0x55, 0x96, 0x38, 0xc7, 0xc5,
                      0x1f, 0x63, 0x52, 0xdb, 0xe4, 0x96, 0x5f, 0xc2 };

static DPS_Status TestToString(void)
{
    if (strcmp("532710e8-3629-a1e8-e252-eea0d4ba2c1a", DPS_UUIDToString(&a)) ||
        strcmp("c25f96e4-db52-631f-c5c7-38965540f802", DPS_UUIDToString(&b))) {
        return DPS_ERR_FAILURE;
    } else {
        return DPS_OK;
    }
}

static DPS_Status TestCompare(void)
{
    if (DPS_UUIDCompare(&a, &b) < 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_FAILURE;
    }
}

int main(int argc, char** argv)
{
    int i;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    ret = TestToString();
    CHECK(ret);
    ret = TestCompare();
    CHECK(ret);

    printf("Passed\n");
    return EXIT_SUCCESS;

Failed:

    printf("Failed at line %d %s\n", ln, DPS_ErrTxt(ret));
    return EXIT_FAILURE;
}
