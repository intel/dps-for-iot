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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/registration.h>
#include <dps/synchronous.h>
#include "common.h"
#include "keys.h"

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_AckPublication(pub, NULL, 0);
    if (ret != DPS_OK) {
        DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = ++argv;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    DPS_Node* node;
    DPS_Event* nodeDestroyed;
    const char* topics[1];
    DPS_Subscription* subscription;
    DPS_NodeAddress* listenAddr = NULL;
    int subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;

    DPS_Debug = DPS_FALSE;

    while (--argc) {
        if (ListenArg(&arg, &argc, &listenAddr)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (IntArg("-r", &arg, &argc, &subsRate, 0, INT32_MAX)) {
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
    }

    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), NULL);
    DPS_SetNodeSubscriptionUpdateDelay(node, subsRate);

    ret = DPS_StartNode(node, 0, listenAddr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Registration services is listening on %s\n",
              DPS_GetListenAddressString(node));

    nodeDestroyed = DPS_CreateEvent();

    topics[0] = DPS_RegistryTopicString;
    subscription = DPS_CreateSubscription(node, topics, 1);
    ret = DPS_Subscribe(subscription, OnPubMatch);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
        DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    DPS_DestroyAddress(listenAddr);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-l <listen port>] [-d]\n", *argv);
    return 1;
}
