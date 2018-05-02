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
#include "bitvec.h"

#define FILTER_BITS     768 * 8
#define NUM_KEYS        397


static const double Report[] = {
    -1.0, 0.0, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 50.0, 70.0, 80.0, 95.0, 97.0, 98.0, 99.0, 100.0
};

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = argv + 1;
    DPS_BitVector* bf;
    size_t i;
    size_t filterBits = 4096;
    size_t numHashes = 4;
    size_t report = 0;
    const size_t base = 0xa1c46f01;

    while (--argc) {
        char* p;
        if (strcmp(*arg, "-b") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            filterBits = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-n") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            numHashes = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        goto Usage;
    }

    ret = DPS_Configure(filterBits, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }
    bf = DPS_BitVectorAlloc();

    for (i = base; i < (base + filterBits * 2); ++i) {
        double load = DPS_BitVectorLoadFactor(bf);
        if (load > Report[report]) {
            DPS_PRINT("Added %d: ", (int)(i - base));
            DPS_BitVectorDump(bf, 0);
            load = Report[report];
            ++report;
        }
        if (load == 100.0) {
            break;
        }
        DPS_BitVectorBloomInsert(bf, (uint8_t*)&i, sizeof(i));
    }

    DPS_PRINT("Added %d: ", (int)(i - base));
    DPS_BitVectorDump(bf, 0);
    DPS_BitVectorFree(bf);

    return EXIT_SUCCESS;

Usage:

    DPS_PRINT("Usage %s: [-d] [-b <filter-bits>] [-n <num-hashes>]\n", argv[0]);
    return EXIT_FAILURE;
}
