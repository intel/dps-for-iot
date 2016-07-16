#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitvec.h>

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
            printf("Failed %d\n", i);
        }
    }
    
    /* Count false positives */
    for (i = numKeys; i < 100000 * numKeys; ++i) {
        if (DPS_BitVectorBloomTest(bv, (uint8_t*)&i, sizeof(i))) {
            ++falsePositive;
        }
        ++count;
    }
    printf("False positives = %d out of %d\n", falsePositive, count);
    printf("False positive rate = %f%%\n", 100.0 * (float)falsePositive / count);

    return 0;
}
