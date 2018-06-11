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
#include "coap.h"
#include "node.h"

/*
 * Preshared keys for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */
static const DPS_UUID _NetworkKeyId = {
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
};
static const uint8_t _NetworkKey[DPS_AES_256_KEY_LEN] = {
    0x11,0x21,0xbb,0xf4,0x9f,0x5e,0xe5,0x5a,0x11,0x86,0x47,0xe6,0x3d,0xc6,0x59,0xa4,
    0xc3,0x1f,0x16,0x56,0x7f,0x1f,0xb8,0x4d,0xe1,0x09,0x28,0x26,0xd5,0xc0,0xf1,0x34
};
const DPS_KeyId NetworkKeyId = { _NetworkKeyId.val, sizeof(_NetworkKeyId.val) };
const DPS_Key NetworkKey = { DPS_KEY_SYMMETRIC, .symmetric = { _NetworkKey, sizeof(_NetworkKey) } };

#define NUM_KEYS 2

static const DPS_UUID _PskId[NUM_KEYS] = {
    { .val = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 } },
    { .val = { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc } }
};
static const uint8_t _Psk[NUM_KEYS][DPS_AES_256_KEY_LEN] = {
    { 0xf6,0xeb,0xcb,0xa4,0x25,0xdb,0x3b,0x7e,0x73,0x03,0xe6,0x9c,0x60,0x35,0xae,0x11,
      0xae,0x40,0x0b,0x84,0xf0,0x03,0xcc,0xf9,0xce,0x5c,0x5f,0xd0,0xae,0x51,0x0a,0xcc },
    { 0x2a,0x93,0xff,0x6d,0x96,0x7e,0xb3,0x20,0x85,0x80,0x0e,0x21,0xb0,0x7f,0xa7,0xbe,
      0x3f,0x53,0x68,0x57,0xf9,0x3c,0x7a,0x41,0x59,0xab,0x22,0x2c,0xf8,0xcf,0x08,0x21 }
};
const DPS_KeyId PskId[NUM_KEYS] = {
    { _PskId[0].val, sizeof(_PskId[0].val) },
    { _PskId[1].val, sizeof(_PskId[1].val) },
};
const DPS_Key Psk[NUM_KEYS] = {
    { DPS_KEY_SYMMETRIC, .symmetric = { _Psk[0], sizeof(_Psk[0]) } },
    { DPS_KEY_SYMMETRIC, .symmetric = { _Psk[1], sizeof(_Psk[1]) } }
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
        ret = DPS_MulticastSend(data->node->mcastSender, NULL, bufs, A_SIZEOF(bufs), NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_MulticastSend failed: %s\n", DPS_ErrTxt(ret));
            exit(EXIT_FAILURE);
        }
        DPS_NetFreeBufs(bufs, 2);
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
    int type = DPS_MSG_TYPE_PUB;
    int port = 0;
    int encrypt = DPS_TRUE;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
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
        if (IntArg("-p", &arg, &argc, &port, 1, UINT16_MAX)) {
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
            DPS_SetContentKey(memoryKeyStore, &PskId[i], &Psk[i]);
        }
        DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    }

    nodeDestroyed = DPS_CreateEvent();

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), NULL);
    ret = DPS_StartNode(node, mcast, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    DPS_PRINT("Node is listening on port %d\n", DPS_GetPortNumber(node));
    NetSend(node, &ep, version, type);

    DPS_TimedWaitForEvent(nodeDestroyed, 2000);

    DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    return EXIT_SUCCESS;

Usage:
    DPS_PRINT("Usage %s [-d] [-x 0/1] [-p <portnum>] [-v version] [-t type]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -x: Enable or disable encryption. Default is encryption enabled.\n");
    DPS_PRINT("       -p: A port to send to.\n");
    DPS_PRINT("       -v: The version number to send.\n");
    DPS_PRINT("       -t: The message type to send.\n");
    return EXIT_FAILURE;
}
