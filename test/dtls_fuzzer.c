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
#include <uv.h>

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

uv_udp_recv_cb Fuzz_OnData(DPS_Node* node, uv_udp_recv_cb cb);

static uv_udp_recv_cb dataCB = NULL;
static uv_udp_recv_cb serverDataCB = NULL;
static int serverStep;
static uv_udp_recv_cb clientDataCB = NULL;
static int clientStep;

static char* fuzzRole = "server";
static int fuzzStep = 0;
static uv_buf_t fuzzData;

static DPS_MemoryKeyStore* CreateKeyStore()
{
    DPS_MemoryKeyStore* keyStore;
    size_t i;
    const Id* id;

    keyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(keyStore, &NetworkKeyId, &NetworkKey);
    for (i = 0; i < NUM_KEYS; ++i) {
        DPS_SetContentKey(keyStore, &PskId[i], &Psk[i]);
    }
    DPS_SetTrustedCA(keyStore, TrustedCAs);
    for (id = Ids; id->keyId.id; ++id) {
        DPS_SetCertificate(keyStore, id->cert, id->privateKey, id->password);
    }
    return keyStore;
}

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t len)
{
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

typedef struct {
    DPS_Event* event;
    DPS_MemoryKeyStore* keyStore;
    DPS_Node* node;
} Node;

static void DestroyNode(Node* node)
{
    DPS_Status ret;

    if (node) {
        if (node->node) {
            ret = DPS_DestroyNode(node->node, OnNodeDestroyed, node->event);
            if (ret == DPS_OK) {
                DPS_WaitForEvent(node->event);
            }
        }
        if (node->keyStore) {
            DPS_DestroyMemoryKeyStore(node->keyStore);
        }
        if (node->event) {
            DPS_DestroyEvent(node->event);
        }
        free(node);
    }
}

static Node* CreateNode()
{
    Node* node = NULL;
    DPS_Status ret;

    node = calloc(1, sizeof(Node));
    if (!node) {
        goto ErrorExit;
    }
    node->event = DPS_CreateEvent();
    if (!node->event) {
        goto ErrorExit;
    }
    node->keyStore = CreateKeyStore();
    if (!node->keyStore) {
        goto ErrorExit;
    }
    node->node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(node->keyStore), NULL);
    if (!node) {
        goto ErrorExit;
    }
    DPS_SetNodeSubscriptionUpdateDelay(node->node, 10);
    ret = DPS_StartNode(node->node, DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV, NULL);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    return node;

ErrorExit:
    DestroyNode(node);
    return NULL;
}

static void OnData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    return dataCB(socket, nread, buf, addr, flags);
}

static void OnServerData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    if (nread > 0) {
        if (serverStep == fuzzStep) {
            assert(fuzzData.len <= buf->len);
            memcpy(buf->base, fuzzData.base, fuzzData.len);
        } else if (fuzzStep == -1) {
            char template[] = "NNN-XXXXXX.dat";
            sprintf(template, "%d-XXXXXX.dat", serverStep);
            int fd = mkstemps(template, 4);
            (void)write(fd, buf->base, nread);
            close(fd);
        }
        ++serverStep;
    }
    return serverDataCB(socket, nread, buf, addr, flags);
}

static void OnClientData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    if (nread > 0) {
        if (fuzzStep == -1) {
            char template[] = "NNN-XXXXXX.dat";
            sprintf(template, "%d-XXXXXX.dat", clientStep);
            int fd = mkstemps(template, 4);
            (void)write(fd, buf->base, nread);
            close(fd);
        }
        ++clientStep;
    }
    return clientDataCB(socket, nread, buf, addr, flags);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    /* Get the role and step and remove from the input args */
    fuzzRole = (*argv)[1];
    fuzzStep = atoi((*argv)[2]);
    *argc -= 2;
    for (int i = 1; i < *argc; ++i) {
        (*argv)[i] = (*argv)[i + 2];
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
    Node* server = NULL;
    Node* client = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Publication* pub = NULL;
    const char *topic = "T";
    DPS_NodeAddress* addr = NULL;
    DPS_Status ret;

    fuzzData.base = (char*)data;
    fuzzData.len = len;

    serverStep = 0;
    server = CreateNode();
    if (!server) {
        goto Exit;
    }
    if (!strcmp(fuzzRole, "server")) {
        serverDataCB = Fuzz_OnData(server->node, OnServerData);
    } else {
        dataCB = Fuzz_OnData(server->node, OnData);
    }
    sub = DPS_CreateSubscription(server->node, &topic, 1);
    if (!sub) {
        goto Exit;
    }
    ret = DPS_Subscribe(sub, PublicationHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }

    clientStep = 0;
    client = CreateNode();
    if (!client) {
        goto Exit;
    }
    if (!strcmp(fuzzRole, "client")) {
        clientDataCB = Fuzz_OnData(client->node, OnClientData);
    } else {
        dataCB = Fuzz_OnData(client->node, OnData);
    }
    pub = DPS_CreatePublication(client->node);
    if (!pub) {
        goto Exit;
    }
    ret = DPS_InitPublication(pub, &topic, 1, DPS_FALSE, NULL, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }

    addr = DPS_CreateAddress();
    if (!addr) {
        goto Exit;
    }
    DPS_LinkTo(client->node, DPS_GetListenAddressString(server->node), addr);

Exit:
    DPS_DestroyAddress(addr);
    DPS_DestroyPublication(pub);
    DestroyNode(client);
    DPS_DestroySubscription(sub);
    DestroyNode(server);
    return 0;
}
