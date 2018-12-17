/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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
#include <dps/compat.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>


static DPS_Node* node;

static DPS_Status OnReceive(DPS_Node* node, DPS_RxBuffer* rxBuf, DPS_Status status)
{
    DPS_PRINT("Received %d bytes\n%s\n", DPS_RxBufferAvail(rxBuf), rxBuf->base);
    return DPS_OK;
}

static char testString[] = "This is a test string";

static DPS_TxBuffer txBuf;

int main(int argc, char** argv)
{
    DPS_Status status;
    int i;
    char** arg = argv + 1;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        goto Usage;
    }

    node = DPS_CreateNode("/");
    status = DPS_NetworkInit(node);
    CHECK(status == DPS_OK);

    status = DPS_MCastStart(node, OnReceive);
    CHECK(status == DPS_OK);

    DPS_TxBufferReserve(node, &txBuf, strlen(testString) + 1, DPS_TX_POOL);
    DPS_TxBufferAppend(&txBuf, testString, strlen(testString) + 1);
    DPS_TxBufferCommit(&txBuf);

    for (i = 0; i < 100; ++i) {
        Sleep(5000);
        DPS_MCastSend(node, NULL, NULL);
    }

    return 0;

failed:
    DPS_PRINT("FAILED (%s) near line %d\r\n", __FILE__, atLine - 1);
    return 1;

Usage:
    DPS_PRINT("Usage %s: [-d]\n", argv[0]);
    return 1;
}
