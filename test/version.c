/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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
#include "coap.h"
#include "node.h"

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

typedef struct _NetSendData {
    DPS_Node* node;
    RemoteNode *remote;
    int version;
    int type;
} NetSendData;

static void OnNetSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* endpoint,
                              uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    DPS_PRINT("OnNetSendComplete(status=%s)\n", DPS_ErrTxt(status));
    DPS_NetFreeBufs(bufs, numBufs);
}

static void NetSendTaskClose(uv_handle_t* handle)
{
    NetSendData* data = (NetSendData*)handle->data;
    free(data);
    free(handle);
}

static void NetSendTask(uv_async_t* handle)
{
    NetSendData* data = (NetSendData*)handle->data;

    /*
     * Not including the entire message as the only point in this test is to
     * exercise the version handling.
     */
    size_t len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_MAP(0) +
        CBOR_SIZEOF_MAP(0) +
        CBOR_SIZEOF_MAP(0);
    DPS_TxBuffer buf;
    int ret = DPS_TxBufferInit(&buf, NULL, len);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, data->version);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, data->type);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    uv_buf_t bufs[] = {
        uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf))
    };

    if (((struct sockaddr_in*)&data->remote->ep.addr.u.inaddr)->sin_port) {
        ret = DPS_NetSend(data->node, NULL, &data->remote->ep, bufs, A_SIZEOF(bufs), OnNetSendComplete);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_NetSend failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
    } else {
        ret = DPS_MulticastSend(data->node->mcastSender, NULL, bufs, A_SIZEOF(bufs), NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_MulticastSend failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
        DPS_NetFreeBufs(bufs, 1);
    }

    uv_close((uv_handle_t*)handle, NetSendTaskClose);
}

static void NetSend(DPS_Node* node, DPS_NetEndpoint* ep, int version, int type)
{
    NetSendData* data;
    uv_async_t* async;
    int ret;
    DPS_Status status;

    data = malloc(sizeof(NetSendData));
    if (!data) {
        DPS_ERRPRINT("Out of memory\n");
        exit(EXIT_FAILURE);
    }
    data->node = node;
    DPS_LockNode(node);
    status = DPS_AddRemoteNode(node, &ep->addr, NULL, &data->remote);
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_AddRemoteNode failed: %s\n", DPS_ErrTxt(status));
        exit(EXIT_FAILURE);
    }
    DPS_UnlockNode(node);
    data->version = version;
    data->type = type;

    async = malloc(sizeof(uv_async_t));
    if (!async) {
        DPS_ERRPRINT("Out of memory\n");
        exit(EXIT_FAILURE);
    }
    async->data = data;
    ret = uv_async_init(node->loop, async, NetSendTask);
    if (ret < 0) {
        DPS_ERRPRINT("uv_async_init failed: %s\n", uv_strerror(ret));
        exit(EXIT_FAILURE);
    }
    ret = uv_async_send(async);
    if (ret < 0) {
        DPS_ERRPRINT("uv_async_send failed: %s\n", uv_strerror(ret));
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    int version = 1;
    int type = DPS_MSG_TYPE_PUB;
    int encrypt = DPS_TRUE;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_NetEndpoint ep;
    DPS_Node *node = NULL;
    DPS_Event* nodeDestroyed = NULL;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (IntArg("-v", &arg, &argc, &version, 1, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-t", &arg, &argc, &type, 1, UINT8_MAX)) {
            continue;
        }
        if (AddressArg("-p", &arg, &argc, &addr)) {
            continue;
        }
        if (IntArg("-x", &arg, &argc, &encrypt, 0, 1)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
    }
    memset(&ep, 0, sizeof(ep));
    if (addr) {
        mcast = DPS_MCAST_PUB_DISABLED;
        DPS_CopyAddress(&ep.addr, addr);
    }
    if (encrypt) {
        size_t i;
        memoryKeyStore = DPS_CreateMemoryKeyStore();
        for (i = 0; i < NUM_KEYS; ++i) {
            DPS_SetContentKey(memoryKeyStore, &PskId[i], &Psk[i]);
        }
        DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    }

    nodeDestroyed = DPS_CreateEvent();

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), NULL);
    ret = DPS_StartNode(node, mcast, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    DPS_PRINT("Node is listening on %s\n", DPS_GetListenAddressString(node));
    NetSend(node, &ep, version, type);

    DPS_TimedWaitForEvent(nodeDestroyed, 2000);

    DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    DPS_DestroyAddress(addr);
    return EXIT_SUCCESS;

Usage:
    DPS_PRINT("Usage %s [-d] [-x 0/1] [-p <address>] [-v version] [-t type]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -x: Enable or disable encryption. Default is encryption enabled.\n");
    DPS_PRINT("       -p: An address to send to.\n");
    DPS_PRINT("       -v: The version number to send.\n");
    DPS_PRINT("       -t: The message type to send.\n");
    return EXIT_FAILURE;
}
