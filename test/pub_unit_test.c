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
#include "keys.h"
#include <dps/compat.h>
#include <dps/dps.h>
#include <dps/private/dps.h>
#include <dps/private/pub.h>
#include <dps/private/network.h>


static DPS_Node* node;

static DPS_Status OnReceive(DPS_Node* node, DPS_RxBuffer* rxBuf, DPS_Status status)
{
    DPS_PRINT("Received %d bytes\n%s\n", DPS_RxBufferAvail(rxBuf), rxBuf->base);
    return DPS_OK;
}

static char testString[] = "This is a test string";

static DPS_TxBuffer txBuf;

#define NUM_TOPICS 2

static const char* topics[NUM_TOPICS] = {
    "red/green/blue",
    "a/b/c/d"
};

int main(int argc, char** argv)
{
    DPS_KeyStore* keyStore = NULL;
    DPS_Publication pub;
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

    node = DPS_Init();

    /* For testing purposes manually add keys to the key store */
    keyStore = DPS_GetKeyStore(node);
    for (i = 0; i < NUM_KEYS; ++i) {
        DPS_SetContentKey(keyStore, &PskId[i], &Psk[i]);
    }

    status = DPS_NetworkInit(node);
    CHECK(status == DPS_OK);

    status = DPS_MCastStart(node, OnReceive);
    CHECK(status == DPS_OK);

    /* Initialize publicaton with a pre-shared key */
    status = DPS_InitPublication(node, &pub, topics, NUM_TOPICS, DPS_FALSE, &PskId[1], NULL);
    CHECK(status == DPS_OK);


    for (i = 0; i < 10; ++i) {
        status = DPS_Publish(&pub, (const uint8_t*)testString, strlen(testString) + 1, 0);
        CHECK(status == DPS_OK);
        Sleep(5000);
    }

    return 0;

failed:
    DPS_PRINT("FAILED: status=%s (%s) near line %d\r\n", DPS_ErrTxt(status), __FILE__, atLine - 1);
    return 1;

Usage:
    DPS_PRINT("Usage %s: [-d]\n", argv[0]);
    return 1;
}
