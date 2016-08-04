#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitvec.h>

#define BITLEN  64

static void SetBits(DPS_BitVector* bv, uint8_t n)
{
    static uint8_t buf[BITLEN / 8];

    memset(buf, n, sizeof(buf));
    DPS_BitVectorSet(bv, buf, sizeof(buf));
}

int main(int argc, char** argv)
{
    DPS_BitVector* bv;
    DPS_BitVector* bvU;
    DPS_BitVector* bvI;
    DPS_CountVector* cv;

    DPS_Configure(BITLEN, 4);

    bv = DPS_BitVectorAlloc();
    cv = DPS_CountVectorAlloc();

    SetBits(bv, 0x01);
    DPS_CountVectorAdd(cv, bv);
    DPS_CountVectorDump(cv);
    SetBits(bv, 0x80);
    DPS_CountVectorAdd(cv, bv);
    DPS_CountVectorDump(cv);
    SetBits(bv, 0xFF);
    DPS_CountVectorAdd(cv, bv);
    DPS_CountVectorDump(cv);

    SetBits(bv, 0xFF);
    DPS_CountVectorDel(cv, bv);
    DPS_CountVectorDump(cv);

    SetBits(bv, 0x01);
    DPS_CountVectorDel(cv, bv);
    SetBits(bv, 0x80);
    DPS_CountVectorDel(cv, bv);
    DPS_CountVectorDump(cv);

    SetBits(bv, 0x01);
    DPS_CountVectorAdd(cv, bv);
    SetBits(bv, 0x03);
    DPS_CountVectorAdd(cv, bv);

    DPS_CountVectorDump(cv);

    bvU = DPS_CountVectorToUnion(cv);
    DPS_BitVectorDump(bvU, 1);

    bvI = DPS_CountVectorToIntersection(cv);
    DPS_BitVectorDump(bvI, 1);

    return 0;
}
