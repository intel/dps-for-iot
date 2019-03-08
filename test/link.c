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

#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
static const char* GetService(DPS_Node* node)
{
    static char service[8];
    uint16_t port = 0;

    const DPS_NodeAddress* addr = DPS_GetListenAddress(node);
    if (addr->u.inaddr.ss_family == AF_INET6) {
        const struct sockaddr_in6* ip6 = (const struct sockaddr_in6*)&addr->u.inaddr;
        port = ntohs(ip6->sin6_port);
    } else {
        const struct sockaddr_in* ip4 = (const struct sockaddr_in*)&addr->u.inaddr;
        port = ntohs(ip4->sin_port);
    }
    snprintf(service, sizeof(service), "%d", port);
    return service;
}
#endif

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

    /* TODO until DPS_Resolve gets sorted out for pipes */
#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    addr = DPS_CreateAddress();
    ret = DPS_ResolveAddressSyn(a, NULL, GetService(b), addr);
    ASSERT(ret == DPS_OK);
#elif defined(DPS_USE_PIPE)
    addr = (DPS_NodeAddress*)DPS_GetListenAddress(b);
#endif
    ret = DPS_LinkTo(a, addr);
    ASSERT(ret == DPS_OK);
#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    DPS_DestroyAddress(addr);
#endif

#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    addr = DPS_CreateAddress();
    ret = DPS_ResolveAddressSyn(b, NULL, GetService(a), addr);
    ASSERT(ret == DPS_OK);
#elif defined(DPS_USE_PIPE)
    addr = (DPS_NodeAddress*)DPS_GetListenAddress(a);
#endif
    ret = DPS_LinkTo(b, addr);
    ASSERT(ret == DPS_OK);
#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    DPS_DestroyAddress(addr);
#endif

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
