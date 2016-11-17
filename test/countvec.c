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
