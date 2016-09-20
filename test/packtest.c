#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dps/topics.h>
#include <dps/dps_dbg.h>

static uint8_t packed[10000];

#define NUM_TESTS 13

static void InitBitVector(DPS_BitVector* bf, size_t len, int testCase)
{
    DPS_Status ret;
    size_t i;
    uint8_t* data;

    data = malloc(len);
    switch (testCase) {
    case 0:
        memset(data, 0, len);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 1:
        memset(data, 0xFF, len);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 2:
        memset(data, 0x55, len);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 3:
        memset(data, 0xAA, len);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 4:
        memset(data, 0xFF, len);
        data[len - 1] = 0x7F;
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 5:
        memset(data, 0, len);
        data[len - 1] = 0x80;
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 6:
        memset(data, 0, len);
        memset(data, 0x55, len / 2);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 7:
        memset(data, 0x55, len);
        memset(data, 0, len / 2);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 8:
        memset(data, 0xCC, len);
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 9:
        for (i = 0; i < len; ++i) {
            data[i] = i;
        }
        ret = DPS_BitVectorSet(bf, data, len);
        break;
    case 10:
        ret = DPS_AddTopic(bf, "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v", ".", DPS_Pub);
        break;
    case 11:
        ret = DPS_AddTopic(bf, "foo.bar.y", ".", DPS_Pub);
        ret = DPS_AddTopic(bf, "red", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "blue", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "green", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/bar", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/baz", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn", "/", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.x", "/.", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.y", "/.", DPS_Pub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.z", "/.", DPS_Pub);
        ret = DPS_AddTopic(bf, "razz/baz/x=1", "/=", DPS_Pub);
        ret = DPS_AddTopic(bf, "razz/baz/x=2", "/=", DPS_Pub);
        ret = DPS_AddTopic(bf, "razz/baz/x=3", "/=", DPS_Pub);
        ret = DPS_AddTopic(bf, "razz/baz/x=4", "/=", DPS_Pub);
        ret = DPS_AddTopic(bf, "razz/baz/x=5", "/=", DPS_Pub);
        break;
    case 12:
        ret = DPS_AddTopic(bf, "foo.bar.y", ".", DPS_Sub);
        ret = DPS_AddTopic(bf, "red", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "blue", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "green", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/bar", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/baz", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn", "/", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.x", "/.", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.y", "/.", DPS_Sub);
        ret = DPS_AddTopic(bf, "foo/baz/gorn.z", "/.", DPS_Sub);
        ret = DPS_AddTopic(bf, "razz/baz/x=1", "/=", DPS_Sub);
        ret = DPS_AddTopic(bf, "razz/baz/x=2", "/=", DPS_Sub);
        ret = DPS_AddTopic(bf, "razz/baz/x=3", "/=", DPS_Sub);
        ret = DPS_AddTopic(bf, "razz/baz/x=4", "/=", DPS_Sub);
        ret = DPS_AddTopic(bf, "razz/baz/x=5", "/=", DPS_Sub);
        break;
    }
    assert(ret == DPS_OK);
    free(data);
    DPS_BitVectorDump(bf, 1);
}


static void RunTests(DPS_BitVector* pubBf, size_t size)
{
    size_t i;
    DPS_Status ret;
    DPS_Buffer buffer;
    DPS_BitVector* bf;
    int cmp;

    for (i = 0; i < NUM_TESTS; ++i) {

        DPS_BufferInit(&buffer, packed, sizeof(packed));

        InitBitVector(pubBf, size, i);

        ret = DPS_BitVectorSerialize(pubBf, &buffer);
        assert(ret == DPS_OK);
        /*
         * Switch over from writing to reading
         */
        DPS_BufferInit(&buffer, packed, DPS_BufferUsed(&buffer));

        bf = DPS_BitVectorAlloc();
        ret = DPS_BitVectorDeserialize(bf, &buffer);
        assert(ret == DPS_OK);

        cmp = DPS_BitVectorEquals(bf, pubBf);
        assert(cmp == 1);

        DPS_BitVectorFree(bf);
        DPS_BitVectorClear(pubBf);
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_BitVector* bf;
    size_t filterBits = (argc > 1) ? atoi(argv[1]) : 256;
    size_t numHashes = (argc > 2) ? atoi(argv[2]) : 4;

    if (filterBits <= 0) {
        printf("Usage %s: <filter-bits> [<num-hashes>]\n", argv[0]);
        exit(0);
    }

    ret = DPS_Configure(filterBits, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        return 1;
    }

    bf = DPS_BitVectorAlloc();
    RunTests(bf, filterBits / 8);
    DPS_BitVectorFree(bf);
    return 0;
}
