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

#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/private/network.h>
#include "../node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

struct _DPS_NetContext {
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

struct _DPS_MulticastReceiver {
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

struct _DPS_MulticastSender {
    DPS_Node* node;
};

DPS_NetContext* DPS_NetStart(DPS_Node* node, const DPS_NodeAddress* addr, DPS_OnReceive cb)
{
    DPS_NetContext* netCtx = NULL;

    netCtx = malloc(sizeof(DPS_NetContext));
    if (netCtx) {
        netCtx->node = node;
        netCtx->receiveCB = cb;
    }
    return netCtx;
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    free(netCtx);
}

DPS_NodeAddress* DPS_NetGetListenAddress(DPS_NodeAddress* addr, DPS_NetContext* netCtx)
{
    struct sockaddr_in6* saddr;

    memzero_s(addr, sizeof(DPS_NodeAddress));
    addr->type = DPS_UDP;
    saddr = (struct sockaddr_in6*)&addr->u.inaddr;
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = 10000;
    memcpy(&saddr->sin6_addr, &in6addr_any, sizeof(saddr->sin6_addr));
    return addr;
}

DPS_Status DPS_NetSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* endpoint,
                       uv_buf_t* bufs, size_t numBufs,
                       DPS_NetSendComplete sendCompleteCB)
{
    return DPS_ERR_NOT_IMPLEMENTED;
}

void DPS_NetConnectionIncRef(DPS_NetConnection* cn)
{
}

void DPS_NetConnectionDecRef(DPS_NetConnection* cn)
{
}

DPS_MulticastReceiver* DPS_MulticastStartReceive(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_MulticastReceiver* receiver = NULL;

    receiver = malloc(sizeof(DPS_MulticastReceiver));
    if (receiver) {
        receiver->node = node;
        receiver->receiveCB = cb;
    }
    return receiver;
}

void DPS_MulticastStopReceive(DPS_MulticastReceiver* receiver)
{
    free(receiver);
}

DPS_MulticastSender* DPS_MulticastStartSend(DPS_Node* node)
{
    DPS_MulticastSender* sender = NULL;

    sender = malloc(sizeof(DPS_MulticastSender));
    if (sender) {
        sender->node = node;
    }
    return sender;
}

void DPS_MulticastStopSend(DPS_MulticastSender* sender)
{
    free(sender);
}

DPS_Status DPS_MulticastSend(DPS_MulticastSender* sender, void* appCtx, uv_buf_t* bufs, size_t numBufs, DPS_MulticastSendComplete sendCompleteCB)
{
    return DPS_ERR_NOT_IMPLEMENTED;
}

void Fuzz_OnNetReceive(DPS_Node* node, const uint8_t* data, size_t len)
{
    DPS_NetEndpoint ep;
    struct sockaddr_in sa;
    DPS_NetRxBuffer* buf;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    DPS_NetSetAddr(&ep.addr, DPS_UDP, (const struct sockaddr *)&sa);
    DPS_EndpointSetPort(&ep, 10001);
    ep.cn = NULL;
    buf = DPS_CreateNetRxBuffer(len);
    if (!buf) {
        DPS_ERRPRINT("Create buffer failed\n");
        return;
    }
    memcpy(buf->rx.rxPos, data, len);
    node->netCtx->receiveCB(node, &ep, DPS_OK, buf);
    DPS_NetRxBufferDecRef(buf);
}

void Fuzz_OnMulticastReceive(DPS_Node* node, const uint8_t* data, size_t len)
{
    DPS_NetEndpoint ep;
    struct sockaddr_in sa;
    DPS_NetRxBuffer* buf;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    DPS_NetSetAddr(&ep.addr, DPS_UDP, (const struct sockaddr *)&sa);
    DPS_EndpointSetPort(&ep, 10001);
    ep.cn = NULL;
    buf = DPS_CreateNetRxBuffer(len);
    if (!buf) {
        DPS_ERRPRINT("Create buffer failed\n");
        return;
    }
    memcpy(buf->rx.rxPos, data, len);
    node->mcastReceiver->receiveCB(node, &ep, DPS_OK, buf);
    DPS_NetRxBufferDecRef(buf);
}
