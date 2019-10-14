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

static DPS_MemoryKeyStore* CreateKeyStore(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;

    keyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(keyStore, &NetworkKeyId, &NetworkKey);
    return keyStore;
}

static void DestroyKeyStore(DPS_MemoryKeyStore* keyStore)
{
    DPS_DestroyMemoryKeyStore(keyStore);
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

static DPS_Node* CreateNode(DPS_MemoryKeyStore* keyStore)
{
    DPS_Node *node = NULL;
    DPS_Status ret;

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), NULL);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, NULL);
    ASSERT(ret == DPS_OK);
    return node;
}

static void TestRemoteLinkedAlready(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_ERR_EXISTS);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret == DPS_ERR_EXISTS);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void TestLinkUnlink(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);

    ret = DPS_UnlinkFrom(a, addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void OnLink(DPS_Node* node, const DPS_NodeAddress* addr, DPS_Status status, void* data)
{
}

static void OnUnlink(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
}

static void TestUnlinkWhileLinkInProgress(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    addr = DPS_SetAddress(addr, DPS_GetListenAddressString(b));
    ASSERT(addr);

    /* Skip the resolution step of DPS_Link in order to test unlink while link in progress */
    ret = DPS_LinkRemoteAddr(a, addr, OnLink, NULL);
    ASSERT(ret == DPS_OK);

    ret = DPS_Unlink(a, addr, OnUnlink, NULL);
    ASSERT(ret == DPS_ERR_BUSY);

    DPS_DestroyAddress(addr);
    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
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
    TestLinkUnlink();
    TestUnlinkWhileLinkInProgress();

    /*
     * For clean valgrind results, wait for node thread to exit
     * completely.
     */
    SLEEP(10);
    return EXIT_SUCCESS;
}
