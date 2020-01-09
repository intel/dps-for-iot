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
#include "node.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

typedef struct _ResolveRequest {
    DPS_NodeAddress* addr;
    DPS_Event* event;
} ResolveRequest;

static void OnResolveAddress(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
    ResolveRequest* req = (ResolveRequest*)data;
    DPS_CopyAddress(req->addr, addr);
    DPS_SignalEvent(req->event, DPS_OK);
}

static DPS_NodeAddress* GetListenAddress(DPS_Node* node)
{
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    char host[DPS_MAX_HOST_LEN + 1];
    char service[DPS_MAX_SERVICE_LEN + 1];
    ResolveRequest req;
#endif
    DPS_Status ret;

    addr = DPS_CreateAddress();
    if (!addr) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
#if defined(DPS_USE_DTLS) || defined(DPS_USE_TCP) || defined(DPS_USE_UDP)
    ret = DPS_SplitAddress(DPS_GetListenAddressString(node),
                           host, sizeof(host), service, sizeof(service));
    if (ret != DPS_OK) {
        goto Exit;
    }
    event = DPS_CreateEvent();
    if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    req.addr = addr;
    req.event = event;
    ret = DPS_ResolveAddress(node, host, service, OnResolveAddress, &req);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_WaitForEvent(event);
#elif defined(DPS_USE_PIPE)
    DPS_CopyAddress(addr, DPS_GetListenAddress(node));
    ret = DPS_OK;
#endif
 Exit:
    DPS_DestroyEvent(event);
    if (ret != DPS_OK) {
        DPS_DestroyAddress(addr);
        addr = NULL;
    }
    return addr;
}

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

static DPS_Node* CreateNodeWithId(DPS_MemoryKeyStore* keyStore, const DPS_KeyId* keyId)
{
    DPS_Node *node = NULL;
    DPS_Status ret;

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), keyId);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, NULL);
    ASSERT(ret == DPS_OK);
    return node;
}

static void OnPublication(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
}

static DPS_Node* CreateSubNode(DPS_MemoryKeyStore* keyStore, const char* topic)
{
    DPS_Node *node = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Status ret;

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), NULL);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, NULL);
    ASSERT(ret == DPS_OK);
    sub = DPS_CreateSubscription(node, &topic, 1);
    ASSERT(sub);
    ret = DPS_SetNodeData(node, sub);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, OnPublication);
    ASSERT(ret == DPS_OK);
    return node;
}

static void DestroySubNode(DPS_Node* node)
{
    DPS_Subscription* sub = DPS_GetNodeData(node);
    DPS_Event* event = NULL;

    DPS_DestroySubscription(sub, NULL);
    event = DPS_CreateEvent();
    ASSERT(event);
    DPS_DestroyNode(node, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
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

    addr = GetListenAddress(b);
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

static void OnShutdown(DPS_Node* node, void* data)
{
    DPS_SignalEvent((DPS_Event*)data, DPS_OK);
}

static void TestLinkShutdown(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);

    ASSERT(a->remoteNodes);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);
    ASSERT(!a->remoteNodes);

    DPS_DestroyEvent(event);
    DPS_DestroyAddress(addr);
    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void TestShutdownWhileLinkInProgress(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = GetListenAddress(b);
    ASSERT(addr);

    ret = DPS_LinkRemoteAddr(a, addr, OnLink, NULL);
    ASSERT(ret == DPS_OK);

    ASSERT(a->remoteNodes);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);
    ASSERT(!a->remoteNodes);

    DPS_DestroyEvent(event);
    DPS_DestroyAddress(addr);
    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void TestShutdownWhenNoLinks(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);

    ASSERT(!a->remoteNodes);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);
    ASSERT(!a->remoteNodes);

    DPS_DestroyEvent(event);
    DPS_DestroyAddress(addr);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void TestShutdownWhileIncomingLinkInProgress(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;
    int count;

    /*
     * Use a SUB node so that we have a transaction in progress while
     * we call shutdown
     */
    keyStore = CreateKeyStore();
    a = CreateSubNode(keyStore, "A");
    b = CreateSubNode(keyStore, "B");

    addr = GetListenAddress(a);
    ASSERT(addr);

    ret = DPS_LinkRemoteAddr(b, addr, OnLink, NULL);
    ASSERT(ret == DPS_OK);

    DPS_LockNode(a);
    while (!a->remoteNodes) {
        DPS_UnlockNode(a);
        DPS_LockNode(a);
    }
    DPS_UnlockNode(a);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);
    /*
     * Give a short amount of time for b to run and delete the remote
     * for a.
     */
    for (count = 0; b->remoteNodes && (count < 10); ++count) {
        SLEEP(10);
    }
    ASSERT(!b->remoteNodes);

    DPS_DestroyEvent(event);
    DPS_DestroyAddress(addr);
    DestroySubNode(b);
    DestroySubNode(a);
    DestroyKeyStore(keyStore);
}

static void TestDestroyShutdown(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Event* destroyEvent = NULL;
    DPS_Event* shutdownEvent = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);

    destroyEvent = DPS_CreateEvent();
    ASSERT(destroyEvent);
    shutdownEvent = DPS_CreateEvent();
    ASSERT(shutdownEvent);

    ret = DPS_DestroyNode(a, OnNodeDestroyed, destroyEvent);
    ASSERT(ret == DPS_OK);
    ret = DPS_ShutdownNode(a, OnShutdown, shutdownEvent);
    ASSERT(ret != DPS_OK);

    DPS_DestroyEvent(shutdownEvent);
    DPS_WaitForEvent(destroyEvent);
    DPS_DestroyEvent(destroyEvent);
    DestroyKeyStore(keyStore);
}

static void TestShutdownShutdownAlready(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);

    event = DPS_CreateEvent();
    ASSERT(event);

    /*
     * It's safe to reuse the event here since the second call is
     * expected to fail
     */
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret != DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);

    ret = DPS_ShutdownNode(a, OnShutdown, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);

    DPS_DestroyEvent(event);
    DPS_DestroyAddress(addr);
    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

static void TestMutualShutdown(void)
{
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Event* eventA = NULL;
    DPS_Event* eventB = NULL;
    DPS_Status ret;

    keyStore = CreateKeyStore();
    a = CreateNode(keyStore);
    b = CreateNode(keyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret == DPS_OK);
    DPS_DestroyAddress(addr);

    ASSERT(a->remoteNodes);
    ASSERT(b->remoteNodes);
    eventA = DPS_CreateEvent();
    ASSERT(eventA);
    eventB = DPS_CreateEvent();
    ASSERT(eventB);
    ret = DPS_ShutdownNode(a, OnShutdown, eventA);
    ASSERT(ret == DPS_OK);
    ret = DPS_ShutdownNode(b, OnShutdown, eventB);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(eventA);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(eventB);
    ASSERT(ret == DPS_OK);
    ASSERT(!a->remoteNodes);
    ASSERT(!b->remoteNodes);

    DPS_DestroyEvent(eventA);
    DPS_DestroyEvent(eventB);
    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(keyStore);
}

#if defined(DPS_USE_DTLS)
static void TestPSKFailure(void)
{
    DPS_MemoryKeyStore* aKeyStore = NULL;
    DPS_MemoryKeyStore* bKeyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    /*
     * aKeyStore contains the PSK, bKeyStore does not
     */
    aKeyStore = CreateKeyStore();
    bKeyStore = DPS_CreateMemoryKeyStore();
    a = CreateNode(aKeyStore);
    b = CreateNode(bKeyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(bKeyStore);
    DestroyKeyStore(aKeyStore);
}

static void TestCertificateMissing(void)
{
    DPS_MemoryKeyStore* aKeyStore = NULL;
    DPS_MemoryKeyStore* bKeyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    /*
     * aKeyStore contains a certificate, bKeyStore does not
     */
    aKeyStore = DPS_CreateMemoryKeyStore();
    ret = DPS_SetTrustedCA(aKeyStore, TrustedCAs);
    ASSERT(ret == DPS_OK);
    ret = DPS_SetCertificate(aKeyStore, Ids[0].cert, Ids[0].privateKey, Ids[0].password);
    ASSERT(ret == DPS_OK);
    a = CreateNodeWithId(aKeyStore, &Ids[0].keyId);

    bKeyStore = DPS_CreateMemoryKeyStore();
    ret = DPS_SetTrustedCA(bKeyStore, TrustedCAs);
    ASSERT(ret == DPS_OK);
    b = CreateNode(bKeyStore);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(bKeyStore);
    DestroyKeyStore(aKeyStore);
}

static void TestCertificateInvalid(void)
{
    DPS_MemoryKeyStore* aKeyStore = NULL;
    DPS_MemoryKeyStore* bKeyStore = NULL;
    DPS_Node* a = NULL;
    DPS_Node* b = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    /*
     * aKeyStore and bKeyStore contain certificates signed by separate
     * CAs so the identity of the remote side cannot be verified
     */
    aKeyStore = DPS_CreateMemoryKeyStore();
    ret = DPS_SetTrustedCA(aKeyStore, TrustedCAs);
    ASSERT(ret == DPS_OK);
    ret = DPS_SetCertificate(aKeyStore, Ids[0].cert, Ids[0].privateKey, Ids[0].password);
    ASSERT(ret == DPS_OK);
    a = CreateNodeWithId(aKeyStore, &Ids[0].keyId);

    bKeyStore = DPS_CreateMemoryKeyStore();
    ret = DPS_SetTrustedCA(bKeyStore, AltCA);
    ASSERT(ret == DPS_OK);
    ret = DPS_SetCertificate(bKeyStore, AltId.cert, AltId.privateKey, AltId.password);
    ASSERT(ret == DPS_OK);
    b = CreateNodeWithId(bKeyStore, &AltId.keyId);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(a, DPS_GetListenAddressString(b), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    addr = DPS_CreateAddress();
    ret = DPS_LinkTo(b, DPS_GetListenAddressString(a), addr);
    ASSERT(ret != DPS_OK);
    DPS_DestroyAddress(addr);

    DestroyNode(b);
    DestroyNode(a);
    DestroyKeyStore(bKeyStore);
    DestroyKeyStore(aKeyStore);
}
#endif /* DPS_USE_DTLS */

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
    TestLinkShutdown();
    TestShutdownWhenNoLinks();
    TestShutdownWhileLinkInProgress();
    TestShutdownWhileIncomingLinkInProgress();
    TestDestroyShutdown();
    TestShutdownShutdownAlready();
    TestMutualShutdown();
#if defined(DPS_USE_DTLS)
    TestPSKFailure();
    TestCertificateMissing();
    TestCertificateInvalid();
#endif

    /*
     * For clean valgrind results, wait for node thread to exit
     * completely.
     */
    SLEEP(10);
    return EXIT_SUCCESS;
}
