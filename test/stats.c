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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bitvec.h"

#define FILTER_BITS     768 * 8
#define NUM_KEYS        397

int main(int argc, char** argv)
{
    DPS_BitVector* bv;
    size_t count = 0;
    size_t falsePositive = 0;
    size_t i;
    size_t filterBits = (argc > 1) ? atoi(argv[1]) : 0;
    size_t numKeys = (argc > 2) ? atoi(argv[2]) : 0;
    size_t numHashes = (argc > 3) ? atoi(argv[3]) : 4;

    if (DPS_Configure(filterBits, numHashes) != DPS_OK) {
        printf("Usage %s: <filter-bits> <num-keys> [<num-hashes>]\n", argv[0]);
        exit(0);
    }
    bv = DPS_BitVectorAlloc();

    for (i = 0; i < numKeys; ++i) {
        DPS_BitVectorBloomInsert(bv, (uint8_t*)&i, sizeof(i));
    }

    DPS_BitVectorDump(bv, 0);

    /* Validate the filter is working */
    for (i = 0; i < numKeys; ++i) {
        if (!DPS_BitVectorBloomTest(bv, (uint8_t*)&i, sizeof(i))) {
            printf("Failed %zd\n", i);
        }
    }

    /* Count false positives */
    for (i = numKeys; i < 100000 * numKeys; ++i) {
        if (DPS_BitVectorBloomTest(bv, (uint8_t*)&i, sizeof(i))) {
            ++falsePositive;
        }
        ++count;
    }
    printf("False positives = %zd out of %zd\n", falsePositive, count);
    printf("False positive rate = %f%%\n", 100.0 * (float)falsePositive / count);

    return 0;
}
