#include <stdio.h>
#include <string.h>
#include "test.h"
#include <dps/private/bitvec.h>


DPS_BitVector bv1;
DPS_BitVector bv2;
DPS_BitVector bv3;

static const char* str1 = "red";
static const char* str2 = "green";
static const char* str3 = "blue";
static const char* str4 = "yellow";


static uint8_t txBuf[1024];
static uint8_t rxBuf[1024];


int main()
{
    DPS_Status status;
    DPS_TxBuffer tx;
    DPS_RxBuffer rx;
    int ok;

    DPS_BitVectorClear(&bv1);
    ok = DPS_BitVectorIsClear(&bv1);
    CHECK(ok);

    DPS_BitVectorClear(&bv2);
    DPS_BitVectorClear(&bv3);

    /* Check insertion is idempotent */
    DPS_BitVectorClear(&bv1);
    DPS_BitVectorClear(&bv2);
    DPS_BitVectorBloomInsert(&bv1, str1, strlen(str1));
    DPS_BitVectorBloomInsert(&bv1, str2, strlen(str2));
    DPS_BitVectorBloomInsert(&bv1, str1, strlen(str1));
    DPS_BitVectorBloomInsert(&bv1, str2, strlen(str2));
    DPS_BitVectorBloomInsert(&bv2, str1, strlen(str1));
    DPS_BitVectorBloomInsert(&bv2, str2, strlen(str2));
    ok = DPS_BitVectorEquals(&bv1, &bv2);
    CHECK(ok);

    DPS_BitVectorClear(&bv1);
    DPS_BitVectorClear(&bv2);

    /* Insertion checks */
    DPS_BitVectorBloomInsert(&bv1, str1, strlen(str1));
    ok = DPS_BitVectorBloomTest(&bv1, str1, strlen(str1));
    CHECK(ok);

    ok = !DPS_BitVectorBloomTest(&bv1, str2, strlen(str2));
    CHECK(ok);

    DPS_BitVectorBloomInsert(&bv1, str2, strlen(str2));
    ok = DPS_BitVectorBloomTest(&bv1, str2, strlen(str2));
    CHECK(ok);

    ok = DPS_BitVectorBloomTest(&bv1, str1, strlen(str1));
    CHECK(ok);

    ok = !DPS_BitVectorBloomTest(&bv1, str3, strlen(str3));
    CHECK(ok);

    DPS_BitVectorBloomInsert(&bv2, str3, strlen(str3));
    DPS_BitVectorDup(&bv3, &bv2);
    ok = DPS_BitVectorEquals(&bv2, &bv3);
    CHECK(ok);

    /* Union */
    DPS_BitVectorUnion(&bv3, &bv1);
    ok = DPS_BitVectorBloomTest(&bv3, str1, strlen(str1));
    CHECK(ok);
    ok = DPS_BitVectorBloomTest(&bv3, str2, strlen(str2));
    CHECK(ok);
    ok = DPS_BitVectorBloomTest(&bv3, str3, strlen(str3));
    CHECK(ok);

    /* Empty Intersection */
    DPS_BitVectorIntersection(&bv3, &bv1, &bv2);
    ok = !DPS_BitVectorBloomTest(&bv3, str1, strlen(str1));
    CHECK(ok);
    ok = !DPS_BitVectorBloomTest(&bv3, str2, strlen(str2));
    CHECK(ok);
    ok = !DPS_BitVectorBloomTest(&bv3, str3, strlen(str3));
    CHECK(ok);

    /* Partial Intersection */
    DPS_BitVectorBloomInsert(&bv2, str1, strlen(str1));
    DPS_BitVectorIntersection(&bv3, &bv1, &bv2);
    ok = DPS_BitVectorBloomTest(&bv3, str1, strlen(str1));
    CHECK(ok);
    ok = !DPS_BitVectorBloomTest(&bv3, str2, strlen(str2));
    CHECK(ok);
    ok = !DPS_BitVectorBloomTest(&bv3, str3, strlen(str3));
    CHECK(ok);

    /* Inclusion */
    ok = DPS_BitVectorIncludes(&bv1, &bv3);
    CHECK(ok);
    ok = !DPS_BitVectorIncludes(&bv3, &bv1);
    CHECK(ok);
    DPS_BitVectorDup(&bv3, &bv2);
    DPS_BitVectorUnion(&bv3, &bv1);
    ok = DPS_BitVectorIncludes(&bv3, &bv1);
    CHECK(ok);
    ok = DPS_BitVectorIncludes(&bv3, &bv2);
    CHECK(ok);

    DPS_BitVectorClear(&bv1);
    DPS_BitVectorBloomInsert(&bv1, str1, strlen(str1));
    DPS_BitVectorBloomInsert(&bv1, str2, strlen(str2));
    DPS_BitVectorBloomInsert(&bv1, str3, strlen(str3));
    DPS_BitVectorBloomInsert(&bv1, str4, strlen(str4));

    /* Serialization */
    DPS_TxBufferInit(&tx, txBuf, sizeof(txBuf));
    status = DPS_BitVectorSerialize(&bv1, &tx);
    CHECK(status == DPS_OK);

    DPS_TxBufferToRx(&tx, &rx);

    /* Deserialization */
    status = DPS_BitVectorDeserialize(&bv2, &rx);
    CHECK(status == DPS_OK);
    ok = DPS_BitVectorEquals(&bv1, &bv2);
    CHECK(ok);

    printf("PASSED (%s)\r\n", __FILE__);
    return 0;

failed:
    printf("FAILED (%s) near line %d\r\n", __FILE__, atLine - 1);
    return 1;
}
