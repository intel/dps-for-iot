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

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void DestroyNode(DPS_Node* node)
{
    DPS_Event* event = NULL;

    event = DPS_CreateEvent();
    ASSERT(event);
    DPS_DestroyNode(node, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
}

static DPS_Node* CreateNode(DPS_KeyStore* keyStore)
{
    DPS_Node *node = NULL;
    DPS_Status ret;

    node = DPS_CreateNode("/.", keyStore, NULL);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, NULL);
    ASSERT(ret == DPS_OK);
    return node;
}

static void TestRemoteLinkedAlready(void)
{
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);

    a = CreateNode(DPS_MemoryKeyStoreHandle(memoryKeyStore));
    b = CreateNode(DPS_MemoryKeyStoreHandle(memoryKeyStore));

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
        }
    }

    TestRemoteLinkedAlready();

    /*
     * For clean valgrind results, wait for node thread to exit
     * completely.
     */
    SLEEP(10);
    return EXIT_SUCCESS;
}
