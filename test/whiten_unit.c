#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bitvec.h>

static uint8_t data[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xC3, 0x20, 0xFF, 0x0F, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00,
    0x00, 0x55, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
};

extern DPS_BitVector* DPS_BitVectorScale_Test(DPS_BitVector* bf, size_t reduction);


int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_BitVector* bf;
    DPS_BitVector* scaled;
    DPS_BitVector* whitened;

    ret = DPS_Configure(sizeof(data) * 8, 4, 2, 10);
    assert(ret == DPS_OK);

    bf = DPS_BitVectorAlloc();
    ret = DPS_BitVectorSet(bf, data, sizeof(data));
    assert(ret == DPS_OK);

    DPS_BitVectorDump(bf, 1);

    scaled = DPS_BitVectorScale_Test(bf, 1);
    assert(scaled);
    DPS_BitVectorDump(scaled, 1);

    scaled = DPS_BitVectorScale_Test(bf, 2);
    assert(scaled);
    DPS_BitVectorDump(scaled, 1);

    scaled = DPS_BitVectorScale_Test(bf, 4);
    assert(scaled);
    DPS_BitVectorDump(scaled, 1);

    scaled = DPS_BitVectorScale_Test(bf, 8);
    assert(scaled);
    DPS_BitVectorDump(scaled, 1);
    
    whitened = DPS_BitVectorWhiten(bf);
    assert(whitened);
    DPS_BitVectorDump(whitened, 1);

    return 0;
}
