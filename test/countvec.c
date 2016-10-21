#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include "bitvec.h"

#define BITLEN  64

static void SetBits(DPS_BitVector* bv, uint8_t n)
{
    static uint8_t buf[BITLEN / 8];

    memset(buf, n, sizeof(buf));
    DPS_BitVectorSet(bv, buf, sizeof(buf));
}

static void TestAdd(DPS_CountVector* cv, uint8_t n)
{
    DPS_BitVector* bv = DPS_BitVectorAlloc();
    DPS_BitVector* bvU;
    DPS_BitVector* bvI;

    DPS_PRINT("Add %02x\n", n);
    SetBits(bv, n);
    DPS_CountVectorAdd(cv, bv);
    DPS_CountVectorDump(cv);

    DPS_PRINT("Union        ");
    bvU = DPS_CountVectorToUnion(cv);
    DPS_BitVectorDump(bvU, 1);
    DPS_PRINT("Intersection ");
    bvI = DPS_CountVectorToIntersection(cv);
    DPS_BitVectorDump(bvI, 1);

    DPS_BitVectorFree(bvI);
    DPS_BitVectorFree(bvU);
    DPS_BitVectorFree(bv);
}

static void TestDel(DPS_CountVector* cv, uint8_t n)
{
    DPS_BitVector* bv = DPS_BitVectorAlloc();
    DPS_BitVector* bvU;
    DPS_BitVector* bvI;

    DPS_PRINT("Del %02x\n", n);
    SetBits(bv, n);
    DPS_CountVectorDel(cv, bv);
    DPS_CountVectorDump(cv);

    DPS_PRINT("Union        ");
    bvU = DPS_CountVectorToUnion(cv);
    DPS_BitVectorDump(bvU, 1);
    DPS_PRINT("Intersection ");
    bvI = DPS_CountVectorToIntersection(cv);
    DPS_BitVectorDump(bvI, 1);

    DPS_BitVectorFree(bvI);
    DPS_BitVectorFree(bvU);
    DPS_BitVectorFree(bv);
}

int main(int argc, char** argv)
{
    DPS_CountVector* cv;

    DPS_Configure(BITLEN, 4);

    cv = DPS_CountVectorAlloc();

    TestAdd(cv, 0x01);
    TestAdd(cv, 0x80);
    TestAdd(cv, 0xFF);

    TestDel(cv, 0xFF);
    TestDel(cv, 0x01);
    TestDel(cv, 0x80);

    TestAdd(cv, 0x01);
    TestAdd(cv, 0x03);

    return 0;
}
