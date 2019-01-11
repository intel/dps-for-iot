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
#include <dps/dps.h>
#include <dps/private/dps.h>
#include <dps/private/pub.h>
#include <dps/private/sub.h>



static char testString[] = "This is a test string";

#define NUM_TOPICS 2

static const char* topics[NUM_TOPICS] = {
    "red/green/blue",
    "a/b/c/d"
};

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_PRINT("Received matching publication\n");
}

int main(int argc, char** argv)
{
    DPS_Node* node;
    DPS_KeyStore* keyStore = NULL;
    DPS_Publication pub;
    DPS_Subscription sub;
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

    /* For testing purposes manually add keys to the key store */
    keyStore = DPS_GetKeyStore(node);
    for (i = 0; i < NUM_KEYS; ++i) {
        DPS_SetContentKey(keyStore, &PskId[i], &Psk[i]);
    }

    status = DPS_Start(node);
    CHECK(status == DPS_OK);

    /* Initialize publication with a pre-shared key */
    status = DPS_InitPublication(node, &pub, topics, NUM_TOPICS, DPS_FALSE, &PskId[1], NULL);
    CHECK(status == DPS_OK);

    status = DPS_InitSubscription(node, &sub, topics, 1);
    CHECK(status == DPS_OK);

    status = DPS_Subscribe(&sub, OnPub, NULL);
    CHECK(status == DPS_OK);

    for (i = 0; i < 10; ++i) {
        status = DPS_Publish(&pub, (const uint8_t*)testString, strlen(testString) + 1, 0);
        CHECK(status == DPS_OK);
        SLEEP(5000);
    }

    return 0;

failed:
    DPS_PRINT("FAILED: status=%s (%s) near line %d\r\n", DPS_ErrTxt(status), __FILE__, atLine - 1);
    return 1;

Usage:
    DPS_PRINT("Usage %s: [-d]\n", argv[0]);
    return 1;
}
