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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/private/cbor.h>
#include "coap.h"
#include "node.h"

#define NUM_KEYS 2

static DPS_UUID keyId[NUM_KEYS] = {
    { .val = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 } },
    { .val = { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc } }
};

/*
 * Preshared keys for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */
static uint8_t keyData[NUM_KEYS][16] = {
    { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
    { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 }
};

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
} NetSendData;

static void OnNetSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* endpoint,
                              uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    DPS_PRINT("OnNetSendComplete(status=%s)\n", DPS_ErrTxt(status));
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
     * Not including body and payload as the only point in this test is to
     * exercise the version handling.
     *  [
     *      version,
     *      type,
     *      { headers },
     *      ...
     *  ]
     */
    size_t len = CBOR_SIZEOF_ARRAY(3) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_MAP(0);
    DPS_TxBuffer buf;
    int ret = DPS_TxBufferInit(&buf, NULL, len);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 3);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, data->version);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_PUB);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    uv_buf_t bufs[] = {
        uv_buf_init(NULL, 0),
        uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf))
    };

    if (((struct sockaddr_in*)&data->remote->ep.addr)->sin_port) {
        ret = DPS_NetSend(data->node, NULL, &data->remote->ep, bufs + 1, A_SIZEOF(bufs) - 1, OnNetSendComplete);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_NetSend failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
    } else {
        ret = CoAP_Wrap(bufs, A_SIZEOF(bufs));
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CoAP_Wrap failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
        ret = DPS_MulticastSend(data->node->mcastSender, bufs, A_SIZEOF(bufs));
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_MulticastSend failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
        DPS_NetFreeBufs(bufs, 2);
    }

    uv_close((uv_handle_t*)handle, NULL);
}

static void NetSend(DPS_Node* node, DPS_NetEndpoint* ep, int version)
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
        DPS_ERRPRINT("DPS_AddREmoteNode failed: %s\n", DPS_ErrTxt(ret));
        exit(EXIT_FAILURE);
    }
    DPS_UnlockNode(node);
    data->version = version;

    async = malloc(sizeof(uv_async_t));
    if (!async) {
        DPS_ERRPRINT("Out of memory\n");
        exit(EXIT_FAILURE);
    }
    async->data = data;
    ret = uv_async_init(DPS_GetLoop(node), async, NetSendTask);
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

static int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return 0;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    int version = 1;
    int port = 0;
    int encrypt = DPS_TRUE;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    const DPS_UUID* nodeKeyId = NULL;
    DPS_NetEndpoint ep;
    DPS_Node *node = NULL;
    DPS_Event* nodeDestroyed = NULL;
    DPS_Status ret;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-v", &arg, &argc, &version, 1, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-p", &arg, &argc, &port, 1, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-x", &arg, &argc, &encrypt, 0, 1)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
    }
    memset(&ep, 0, sizeof(ep));
    if (port) {
        mcast = DPS_MCAST_PUB_DISABLED;
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        DPS_SetAddress(&ep.addr, (const struct sockaddr *) &sa);
        DPS_EndpointSetPort(&ep, port);
    }
    if (encrypt) {
        memoryKeyStore = DPS_CreateMemoryKeyStore();
        for (size_t i = 0; i < NUM_KEYS; ++i) {
            DPS_SetContentKey(memoryKeyStore, &keyId[i], keyData[i], 16);
        }
        nodeKeyId = &keyId[0];
        DPS_SetNetworkKey(memoryKeyStore, "test", 4);
    }

    nodeDestroyed = DPS_CreateEvent();

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), nodeKeyId);
    ret = DPS_StartNode(node, mcast, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    NetSend(node, &ep, version);

    DPS_TimedWaitForEvent(nodeDestroyed, 2000);

    DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    return EXIT_SUCCESS;

Usage:
    DPS_PRINT("Usage %s [-d] [-x 0/1] [-p <portnum>] [-v version]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -x: Enable or disable encryption. Default is encryption enabled.\n");
    DPS_PRINT("       -p: A port to send to.\n");
    DPS_PRINT("       -v: The version number to send.\n");
    return EXIT_FAILURE;
}
