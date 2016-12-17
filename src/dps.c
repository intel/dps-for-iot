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
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include "bitvec.h"
#include "cbor.h"
#include "coap.h"
#include "history.h"
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "ack.h"
#include "topics.h"
#include "uv_extra.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define _MIN_(x, y)  (((x) < (y)) ? (x) : (y))

typedef enum { NO_REQ, SUB_REQ, PUB_REQ, ACK_REQ } RequestType;

typedef enum { LINK_OP, UNLINK_OP } OpType;

typedef struct _OnOpCompletion {
    OpType op;
    void* data;
    DPS_Node* node;
    struct _RemoteNode* remote;
    uv_timer_t timer;
    uv_mutex_t mutex;
    union {
        DPS_OnLinkComplete link;
        DPS_OnUnlinkComplete unlink;
        void* cb;
    } on;
} OnOpCompletion;

#define SEND_SUBS_TASK  0x01
#define SEND_PUBS_TASK  0x02
#define SEND_ACKS_TASK  0x04
#define STOP_NODE_TASK  0x08
#define FIND_ADDR_TASK  0x10

/*
 * How long (in milliseconds) to wait to received a response from a remote
 * node this node is linking with.
 */
#define LINK_RESPONSE_TIMEOUT  5000

/*
 * Forward declaration
 */
static void RunBackgroundTasks(uv_async_t* handle);

void DPS_LockNode(DPS_Node* node)
{
    uv_mutex_lock(&node->nodeMutex);
#ifndef NDEBUG
    ++node->lockCount;
    assert(node->lockCount == 1);
#endif
}

void DPS_UnlockNode(DPS_Node* node)
{
#ifndef NDEBUG
    assert(node->lockCount == 1);
    --node->lockCount;
#endif
    uv_mutex_unlock(&node->nodeMutex);
}

static void ScheduleBackgroundTask(DPS_Node* node, uint8_t task)
{
    DPS_DBGTRACE();
    node->tasks |= task;
    DPS_UnlockNode(node);
    uv_async_send(&node->bgHandler);
    DPS_LockNode(node);
}

#define RemoteNodeAddressText(n)  DPS_NodeAddrToString(&(n)->ep.addr)

void DPS_RxBufferFree(DPS_RxBuffer* buffer)
{
    if (buffer->base) {
        free(buffer->base);
        buffer->base = NULL;
    }
    buffer->rxPos = NULL;
    buffer->eod = NULL;
}

void DPS_TxBufferFree(DPS_TxBuffer* buffer)
{
    if (buffer->base) {
        free(buffer->base);
        buffer->base = NULL;
    }
    buffer->txPos = NULL;
    buffer->eob = NULL;
}

DPS_Status DPS_RxBufferInit(DPS_RxBuffer* buffer, uint8_t* storage, size_t size)
{
    if (!size) {
        buffer->base = NULL;
        buffer->rxPos = NULL;
        buffer->eod = NULL;
    } else {
        assert(storage);
        buffer->base = storage;
        buffer->rxPos = storage;
        buffer->eod = storage + size;
    }
    return DPS_OK;
}

DPS_Status DPS_TxBufferInit(DPS_TxBuffer* buffer, uint8_t* storage, size_t size)
{
    DPS_Status ret = DPS_OK;
    if (!storage && size) {
        storage = malloc(size);
        if (!storage) {
            ret = DPS_ERR_RESOURCES;
            size = 0;
        }
    }
    buffer->base = storage;
    buffer->txPos = storage;
    buffer->eob = storage + size;
    return ret;
}

DPS_Status DPS_TxBufferAppend(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    if (DPS_TxBufferSpace(buffer) < len) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(buffer->txPos, data, len);
    buffer->txPos += len;
    return DPS_OK;
}

void DPS_TxBufferToRx(DPS_TxBuffer* txBuffer, DPS_RxBuffer* rxBuffer)
{
    assert(txBuffer && rxBuffer);
    rxBuffer->base = txBuffer->base;
    rxBuffer->eod = txBuffer->txPos;
    rxBuffer->rxPos = txBuffer->base;
}

void DPS_RxBufferToTx(DPS_RxBuffer* rxBuffer, DPS_TxBuffer* txBuffer)
{
    assert(rxBuffer && txBuffer);
    txBuffer->base = rxBuffer->base;
    txBuffer->eob = rxBuffer->eod;
    txBuffer->txPos = rxBuffer->eod;
}

static void OnTimerClosed(uv_handle_t* handle)
{
    free(handle->data);
}

void DPS_RemoteCompletion(DPS_Node* node, RemoteNode* remote, DPS_Status status)
{
    OnOpCompletion* cpn = remote->completion;
    DPS_NodeAddress addr = remote->ep.addr;

    uv_timer_stop(&cpn->timer);

    remote->completion = NULL;
    DPS_UnlockNode(node);
    if (cpn->op == LINK_OP) {
        cpn->on.link(node, &addr, status, cpn->data);
    } else if (cpn->op == UNLINK_OP) {
        cpn->on.unlink(node, &addr, cpn->data);
    }
    DPS_LockNode(node);
    uv_close((uv_handle_t*)&cpn->timer, OnTimerClosed);
    if (status != DPS_OK) {
        DPS_DeleteRemoteNode(node, remote);
    }
}

static int IsValidRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    RemoteNode* r = node->remoteNodes;

    while (r) {
        if (r == remote) {
            return DPS_TRUE;
        }
        r = r->next;
    }

    return DPS_FALSE;
}

RemoteNode* DPS_DeleteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    RemoteNode* next;

    DPS_DBGTRACE();

    if (!IsValidRemoteNode(node, remote)) {
        return NULL;
    }
    next = remote->next;
    if (node->remoteNodes == remote) {
        node->remoteNodes = next;
    } else {
        RemoteNode* prev = node->remoteNodes;
        while (prev->next != remote) {
            prev = prev->next;
            assert(prev);
        }
        prev->next = next;
    }
    if (remote->inbound.interests) {
        if (DPS_CountVectorDel(node->interests, remote->inbound.interests) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.interests);
    }
    if (remote->inbound.needs) {
        if (DPS_CountVectorDel(node->needs, remote->inbound.needs) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.needs);
    }
    DPS_BitVectorFree(remote->outbound.interests);
    DPS_BitVectorFree(remote->outbound.needs);

    if (remote->completion) {
        DPS_RemoteCompletion(node, remote, DPS_ERR_FAILURE);
    }
    /*
     * This tells the network layer we no longer need to keep connection alive for this address
     */
    DPS_NetConnectionDecRef(remote->ep.cn);
    free(remote);
    return next;
}

static DPS_Status UpdateOutboundInterests(DPS_Node* node, RemoteNode* destNode, DPS_BitVector** outboundInterests)
{
    DPS_Status ret;
    DPS_BitVector* newInterests = NULL;
    DPS_BitVector* newNeeds = NULL;

    DPS_DBGTRACE();

    /*
     * Inbound interests from the node we are updating are excluded from the outbound interests
     */
    if (destNode->inbound.interests) {
        ret = DPS_CountVectorDel(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        newInterests = DPS_CountVectorToUnion(node->interests);
        ret = DPS_CountVectorAdd(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        ret = DPS_CountVectorDel(node->needs, destNode->inbound.needs);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        newNeeds = DPS_CountVectorToIntersection(node->needs);
        ret = DPS_CountVectorAdd(node->needs, destNode->inbound.needs);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
    } else {
        assert(!destNode->inbound.needs);
        newInterests = DPS_CountVectorToUnion(node->interests);
        newNeeds = DPS_CountVectorToIntersection(node->needs);
    }
    if (!newNeeds || !newInterests) {
        ret = DPS_ERR_RESOURCES;
        goto ErrExit;
    }
    /*
     * Don't compute the delta if we are synchronizing outbound interests
     */
    if (destNode->outbound.sync) {
        DPS_BitVectorFree(destNode->outbound.interests);
        destNode->outbound.interests = NULL;
    }
    if (destNode->outbound.interests) {
        int same = DPS_FALSE;
        DPS_BitVectorXor(node->scratch.interests, destNode->outbound.interests, newInterests, &same);
        if (same && DPS_BitVectorEquals(destNode->outbound.needs, newNeeds)) {
            *outboundInterests = NULL;
        } else {
            *outboundInterests = node->scratch.interests;
        }
        DPS_BitVectorFree(destNode->outbound.interests);
        DPS_BitVectorFree(destNode->outbound.needs);
    } else {
        /*
         * Inform receiver we are sycnronizing interests
         */
        destNode->outbound.sync = DPS_TRUE;
        *outboundInterests = newInterests;
    }
    destNode->outbound.interests = newInterests;
    destNode->outbound.needs = newNeeds;

    DPS_DBGPRINT("UpdateOutboundInterests: %s %s\n", RemoteNodeAddressText(destNode), *outboundInterests ? "Changes" : "No Change");
    return DPS_OK;

ErrExit:
    DPS_ERRPRINT("UpdateOutboundInterests: %s\n", DPS_ErrTxt(ret));
    DPS_BitVectorFree(newInterests);
    DPS_BitVectorFree(newNeeds);
    return ret;
}

RemoteNode* DPS_LookupRemoteNode(DPS_Node* node, DPS_NodeAddress* addr)
{
    RemoteNode* remote;

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        if (DPS_SameAddr(&remote->ep.addr, addr)) {
            return remote;
        }
    }
    return NULL;
}

static void OnCompletionTimeout(uv_timer_t* timer)
{
    OnOpCompletion* cpn = (OnOpCompletion*)timer->data;
    DPS_LockNode(cpn->node);
    DPS_RemoteCompletion(cpn->node, cpn->remote, DPS_ERR_TIMEOUT);
    DPS_UnlockNode(cpn->node);
}

static OnOpCompletion* AllocCompletion(DPS_Node* node, RemoteNode* remote, OpType op, void* data, uint16_t ttl, void* cb)
{
    OnOpCompletion* cpn;

    cpn = calloc(1, sizeof(OnOpCompletion));
    if (cpn) {
        cpn->op = op;
        cpn->data = data;
        cpn->node = node;
        cpn->remote = remote;
        cpn->on.cb = cb;

        if (uv_timer_init(node->loop, &cpn->timer)) {
            free(cpn);
            return NULL;
        }
        cpn->timer.data = cpn;
        if (uv_timer_start(&cpn->timer, OnCompletionTimeout, ttl, 0)) {
            uv_close((uv_handle_t*)&cpn->timer, OnTimerClosed);
            return NULL;
        }
    }
    return cpn;
}

/*
 * Add a remote node or return an existing one
 */
DPS_Status DPS_AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, DPS_NetConnection* cn, RemoteNode** remoteOut)
{
    RemoteNode* remote = DPS_LookupRemoteNode(node, addr);
    if (remote) {
        *remoteOut = remote;
        /*
         * AddRef a newly established connection
         */
        if (cn && !remote->ep.cn) {
            DPS_NetConnectionAddRef(cn);
            remote->ep.cn = cn;
        }
        return DPS_ERR_EXISTS;
    }
    remote = calloc(1, sizeof(RemoteNode));
    if (!remote) {
        *remoteOut = NULL;
        return DPS_ERR_RESOURCES;
    }
    DPS_DBGPRINT("Adding new remote node %s\n", DPS_NodeAddrToString(addr));
    remote->ep.addr = *addr;
    remote->ep.cn = cn;
    remote->next = node->remoteNodes;
    node->remoteNodes = remote;
    /*
     * This tells the network layer to keep connection alive for this address
     */
    DPS_NetConnectionAddRef(cn);
    *remoteOut = remote;
    return DPS_OK;
}

void DPS_SendFailed(DPS_Node* node, DPS_NodeAddress* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    RemoteNode* remote;

    DPS_DBGPRINT("NetSendFailed %s\n", DPS_ErrTxt(status));
    remote = DPS_LookupRemoteNode(node, addr);
    if (remote) {
        DPS_DeleteRemoteNode(node, remote);
        DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(addr));
    }
    DPS_NetFreeBufs(bufs, numBufs);
}

void DPS_OnSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        RemoteNode* remote;

        DPS_LockNode(node);
        remote = DPS_LookupRemoteNode(node, &ep->addr);
        DPS_DBGPRINT("NetSendComplete %s\n", DPS_ErrTxt(status));
        if (remote) {
            DPS_DeleteRemoteNode(node, remote);
            DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&ep->addr));
        }
        DPS_UnlockNode(node);
    }
    DPS_NetFreeBufs(bufs, numBufs);
}

/*
 * Add this publication to the history record
 */
static DPS_BitVector* PubSubMatch(DPS_Node* node, DPS_Publication* pub, RemoteNode* subscriber)
{
    DPS_BitVectorIntersection(node->scratch.interests, pub->bf, subscriber->inbound.interests);
    DPS_BitVectorFuzzyHash(node->scratch.needs, node->scratch.interests);
    if (DPS_BitVectorIncludes(node->scratch.needs, subscriber->inbound.needs)) {
        /*
         * If the publication will be retained we send the full publication Bloom
         * filter otherwise we only send the intersection with the subscription interests.
         * The reason for sending the full publication is that we don't know what the
         * interests will be over the lifetime of the publication.
         */
        return (pub->flags & PUB_FLAG_RETAINED) ? pub->bf : node->scratch.interests;
    } else {
        return NULL;
    }
}

static DPS_Status SendMatchingPubToSub(DPS_Node* node, DPS_Publication* pub, RemoteNode* subscriber)
{
    /*
     * We don't send publications to remote nodes we have received them from.
     */
    if (!DPS_PublicationReceivedFrom(&node->history, &pub->pubId, pub->sequenceNum, &pub->sender, &subscriber->ep.addr)) {
        DPS_BitVector* pubBV = PubSubMatch(node, pub, subscriber);
        if (pubBV) {
            DPS_DBGPRINT("Sending pub %d to %s\n", pub->sequenceNum, RemoteNodeAddressText(subscriber));
            return DPS_SendPublication(node, pub, pubBV, subscriber);
        }
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->sequenceNum, RemoteNodeAddressText(subscriber));
    }
    return DPS_OK;
}

static void SendAcksTask(DPS_Node* node)
{
    PublicationAck* ack;

    DPS_DBGTRACE();

    while ((ack = node->ackQueue.first) != NULL) {
        RemoteNode* ackNode;
        DPS_Status ret = DPS_AddRemoteNode(node, &ack->destAddr, NULL, &ackNode);
        if (ret == DPS_OK || ret == DPS_ERR_EXISTS) {
            DPS_SendAcknowledgment(node, ack, ackNode);
        }
        node->ackQueue.first = ack->next;
        DPS_DestroyAck(ack);
    }
    node->ackQueue.last = NULL;
}

static void SendPubsTask(DPS_Node* node)
{
    DPS_Publication* pub;
    DPS_Publication* nextPub;

    DPS_DBGTRACE();

    /*
     * Check if any local or retained publications need to be forwarded to this subscriber
     */
    for (pub = node->publications; pub != NULL; pub = nextPub) {
        nextPub = pub->next;
        /*
         * Only check publications that are flagged to be checked
         */
        if (pub->checkToSend) {
            DPS_Status ret;
            RemoteNode* remote;
            RemoteNode* nextRemote;
            /*
             * If the node is a multicast sender local publications are always multicast
             */
            if (node->mcastSender && (pub->flags & PUB_FLAG_LOCAL)) {
                ret = DPS_SendPublication(node, pub, pub->bf, NULL);
                if (ret != DPS_OK) {
                    DPS_ERRPRINT("SendPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
                }
            }
            for (remote = node->remoteNodes; remote != NULL; remote = nextRemote) {
                nextRemote = remote->next;
                if (remote->inbound.interests) {
                    ret = SendMatchingPubToSub(node, pub, remote);
                    if (ret != DPS_OK) {
                        DPS_DeleteRemoteNode(node, remote);
                        DPS_ERRPRINT("SendMatchingPubToSub failed %s\n", DPS_ErrTxt(ret));
                    }
                }
            }
            pub->checkToSend = DPS_FALSE;
        }
        if (uv_now(node->loop) >= pub->expires) {
            DPS_ExpirePub(node, pub);
        }
    }
    DPS_DumpPubs(node);
}

static void SendSubsTask(DPS_Node* node)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote;
    RemoteNode* remoteNext;

    DPS_DBGTRACE();

    /*
     * Forward subscription to all remote nodes with interestss
     */
    for (remote = node->remoteNodes; remote != NULL; remote = remoteNext) {
        DPS_BitVector* newInterests;

        remoteNext = remote->next;

        if (!remote->outbound.checkForUpdates) {
            continue;
        }
        remote->outbound.checkForUpdates = DPS_FALSE;
        if (remote->unlink) {
            DPS_SendSubscription(node, remote, NULL);
            DPS_DBGPRINT("Remote node has been unlinked - deleting\n");
            DPS_DeleteRemoteNode(node, remote);
            continue;
        }
        ret = UpdateOutboundInterests(node, remote, &newInterests);
        if (ret != DPS_OK) {
            break;
        }
        if (newInterests) {
            ret = DPS_SendSubscription(node, remote, newInterests);
            if (ret != DPS_OK) {
                DPS_DeleteRemoteNode(node, remote);
                DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
                ret = DPS_OK;
                continue;
            }
        }
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("SendSubsTask failed %s\n", DPS_ErrTxt(ret));
    }
}

/*
 * Run checks of one or more publications against the current subscriptions
 */
void DPS_UpdatePubs(DPS_Node* node, DPS_Publication* pub)
{
    int count = 0;
    DPS_LockNode(node);

    if (pub) {
        pub->checkToSend = DPS_TRUE;
        ++count;
    } else {
        DPS_Publication* pubNext;
        for (pub = node->publications; pub != NULL; pub = pubNext) {
            pubNext = pub->next;
            /*
             * Received publications are marked as checkToSend they should not be expired.
             */
            if (pub->checkToSend) {
                ++count;
                continue;
            }
            if (uv_now(node->loop) >= pub->expires) {
                DPS_ExpirePub(node, pub);
            } else {
                if ((pub->flags & PUB_FLAG_PUBLISH) && (node->remoteNodes || node->mcastSender)) {
                    pub->checkToSend = DPS_TRUE;
                    ++count;
                }
            }
        }
    }
    if (count) {
        DPS_DBGPRINT("DPS_UpdatePubs %d publications to send\n", count);
        ScheduleBackgroundTask(node, SEND_PUBS_TASK);
    }
    DPS_UnlockNode(node);
}

int DPS_UpdateSubs(DPS_Node* node, RemoteNode* remote)
{
    int count = 0;
    DPS_DBGTRACE();
    DPS_LockNode(node);
    if (node->remoteNodes) {
        if (remote) {
            remote->outbound.checkForUpdates = DPS_TRUE;
            ++count;
        } else {
            /*
             * TODO - when multi-tenancy is implemented subscriptions will only
             * be sent to remotes that match the tenancy criteria. For now we flood
             * subscriptions to all remote nodes.
             */
            for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
                remote->outbound.checkForUpdates = DPS_TRUE;
                ++count;
            }
        }
        if (count) {
            ScheduleBackgroundTask(node, SEND_SUBS_TASK);
        }
    }
    DPS_UnlockNode(node);
    return count;
}

void DPS_QueuePublicationAck(DPS_Node* node, PublicationAck* ack)
{
    DPS_DBGTRACE();

    DPS_LockNode(node);
    if (node->ackQueue.last) {
        node->ackQueue.last->next = ack;
    }
    node->ackQueue.last = ack;
    if (!node->ackQueue.first) {
        node->ackQueue.first = ack;
    }
    ScheduleBackgroundTask(node, SEND_ACKS_TASK);
    DPS_UnlockNode(node);
}

static DPS_Status DecodeRequest(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buf, int multicast)
{
    DPS_Status ret;
    uint8_t msgType;
    size_t len;

    DPS_DBGTRACE();
    CBOR_Dump("Request in", buf->rxPos, DPS_RxBufferAvail(buf));
    ret = CBOR_DecodeArray(buf, &len);
    if (ret != DPS_OK || (len < 2)) {
        DPS_ERRPRINT("Expected a CBOR array or 2 or more elements\n");
        return ret;
    }
    ret = CBOR_DecodeUint8(buf, &msgType);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Expected a message type\n");
        return ret;
    }
    switch (msgType) {
    case DPS_MSG_TYPE_SUB:
        if (len != 3) {
            DPS_ERRPRINT("Expected 3 element array\n");
            break;
        }
        ret = DPS_DecodeSubscription(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscription returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_PUB:
        if (len != 4) {
            DPS_ERRPRINT("Expected 4 element array\n");
            break;
        }
        DPS_DBGPRINT("Received publication via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DPS_DecodePublication(node, ep, buf, multicast);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublication returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_ACK:
        if (len != 3) {
            DPS_ERRPRINT("Expected 3 element array\n");
            break;
        }
        DPS_DBGPRINT("Received acknowledgment via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DPS_DecodeAcknowledgment(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DPS_DecodeAcknowledgment returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    default:
        DPS_ERRPRINT("Invalid message type\n");
        ret = DPS_ERR_INVALID;
        break;
    }
    return ret;
}

/*
 * Using CoAP packetization for receiving multicast subscription requests
 */
static DPS_Status OnMulticastReceive(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Status status, const uint8_t* data, size_t len)
{
    DPS_RxBuffer payload;
    DPS_Status ret;
    CoAP_Parsed coap;

    DPS_DBGTRACE();

    if (!data || !len) {
        return DPS_OK;
    }
    /*
     * Fail input that comes in when the node is no longer running
     */
    if (node->state != DPS_NODE_RUNNING) {
        return DPS_ERR_FAILURE;
    }
    ret = CoAP_Parse(COAP_OVER_UDP, data, len, &coap, &payload);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Discarding garbage multicast packet len=%zu\n", len);
        return ret;
    }
    /*
     * Multicast packets must be non-confirmable
     */
    if (coap.type != COAP_TYPE_NON_CONFIRMABLE) {
        DPS_ERRPRINT("Discarding packet within bad type=%d\n", coap.type);
        return DPS_ERR_INVALID;
    }
    ret = DecodeRequest(node, ep, &payload, DPS_TRUE);
    CoAP_Free(&coap);
    return ret;
}

static DPS_Status OnNetReceive(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Status status, const uint8_t* data, size_t len)
{
    DPS_RxBuffer payload;

    DPS_DBGTRACE();

    /*
     * Fail input that comes in when the node is no longer running
     */
    if (node->state != DPS_NODE_RUNNING) {
        return DPS_ERR_FAILURE;
    }
    /*
     * Delete the remote node if the received failed
     */
    if (status != DPS_OK) {
        RemoteNode* remote;
        DPS_LockNode(node);
        remote = DPS_LookupRemoteNode(node, &ep->addr);
        if (remote) {
            DPS_DeleteRemoteNode(node, remote);
        }
        DPS_UnlockNode(node);
        return status;
    }
    DPS_RxBufferInit(&payload, (uint8_t*)data, len);
    return DecodeRequest(node, ep, &payload, DPS_FALSE);
}

static void StopNode(DPS_Node* node)
{
    DPS_LockNode(node);

    /*
     * Indicates the node is no longer running
     */
    node->state = DPS_NODE_STOPPED;
    /*
     * Stop receivng and close all global handle
     */
    if (node->mcastReceiver) {
        DPS_MulticastStopReceive(node->mcastReceiver);
        node->mcastReceiver = NULL;
    }
    if (node->mcastSender) {
        DPS_MulticastStopSend(node->mcastSender);
        node->mcastSender = NULL;
    }
    if (node->netCtx) {
        DPS_NetStop(node->netCtx);
        node->netCtx = NULL;
    }
    assert(!uv_is_closing((uv_handle_t*)&node->bgHandler));
    uv_close((uv_handle_t*)&node->bgHandler, NULL);
    /*
     * Delete remote nodes and shutdown any connections.
     */
    while (node->remoteNodes) {
        DPS_DeleteRemoteNode(node, node->remoteNodes);
    }
    /*
     * Run the event loop again to ensure that all cleanup is
     * completed
     */
    uv_run(node->loop, UV_RUN_DEFAULT);
    /*
     * Free data structures
     */
    DPS_FreeSubscriptions(node);
    DPS_FreePublications(node);
    DPS_CountVectorFree(node->interests);
    DPS_CountVectorFree(node->needs);
    DPS_BitVectorFree(node->scratch.interests);
    DPS_BitVectorFree(node->scratch.needs);
    DPS_HistoryFree(&node->history);
    /*
     * Cleanup mutexes etc.
     */
    uv_mutex_destroy(&node->condMutex);
    uv_mutex_destroy(&node->history.lock);

    assert(!uv_loop_alive(node->loop));

    uv_loop_close(node->loop);
    free(node->loop);
    /*
     * If we got here before the application called DPS_DestroyNode() we cannot free the node now,
     * it will be freed when DPS_DestroyNode() is called.
     */
    if (node->onDestroyed) {
        DPS_UnlockNode(node);
        node->onDestroyed(node, node->onDestroyedData);
        uv_mutex_destroy(&node->nodeMutex);
        free(node);
    } else {
        DPS_UnlockNode(node);
    }
}

static void NodeRun(void* arg)
{
    int r;
    DPS_Node* node = (DPS_Node*)arg;
    uv_thread_t thisThread = node->thread;

    uv_run(node->loop, UV_RUN_DEFAULT);

    DPS_DBGPRINT("Stopping node\n");
    StopNode(node);

    DPS_DBGPRINT("Exiting node thread\n");

    /*
     * Note: this is not currently a libuv API and is implemented locally
     */
    r = uv_thread_detach(&thisThread);
    if (r) {
        DPS_ERRPRINT("Failed to detatch thread: %s\n", uv_err_name(r));
    }
}

DPS_Node* DPS_CreateNode(const char* separators, DPS_KeyRequestCallback keyRequestCB, DPS_UUID* keyId)
{
    DPS_Node* node = calloc(1, sizeof(DPS_Node));

    if (!node) {
        return NULL;
    }
    /*
     * One time initilization required
     */
    if (DPS_InitUUID() != DPS_OK) {
        free(node);
        return NULL;
    }
    if (!separators) {
        separators = "/";
    }
    if (keyId) {
        node->isSecured = DPS_TRUE;
        memcpy(&node->keyId, keyId, sizeof(DPS_UUID));
    }
    strncpy(node->separators, separators, sizeof(node->separators));
    node->keyRequestCB = keyRequestCB;
    return node;
}

DPS_Status DPS_SetNodeData(DPS_Node* node, void* data)
{
    if (node) {
        node->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetNodeData(const DPS_Node* node)
{
    return node ?  node->userData : NULL;
}

DPS_Status DPS_StartNode(DPS_Node* node, int mcast, int rxPort)
{
    DPS_Status ret = DPS_OK;
    int r;

    if (!node) {
        return DPS_ERR_NULL;
    }
    node->history.loop = node->loop = calloc(1, sizeof(uv_loop_t));
    if (!node->loop) {
        return DPS_ERR_RESOURCES;
    }
    r = uv_loop_init(node->loop);
    if (r) {
        free(node->loop);
        node->loop = NULL;
        node->history.loop = NULL;
        return DPS_ERR_FAILURE;
    }
    DPS_DBGPRINT("libuv version %s\n", uv_version_string());
    /*
     * For triggering background tasks
     */
    node->bgHandler.data = node;
    r = uv_async_init(node->loop, &node->bgHandler, RunBackgroundTasks);
    assert(!r);
    /*
     * Mutex for protecting the node
     */
    r = uv_mutex_init(&node->condMutex);
    assert(!r);
    r = uv_mutex_init(&node->nodeMutex);
    assert(!r);
    r = uv_mutex_init(&node->history.lock);
    assert(!r);

    node->interests = DPS_CountVectorAlloc();
    node->needs = DPS_CountVectorAllocFH();
    node->scratch.interests = DPS_BitVectorAlloc();
    node->scratch.needs = DPS_BitVectorAllocFH();

    if (!node->interests || !node->needs || !node->scratch.interests || !node->scratch.needs) {
        ret = DPS_ERR_RESOURCES;
        goto ErrExit;
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_RECV) {
        node->mcastReceiver = DPS_MulticastStartReceive(node, OnMulticastReceive);
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_SEND) {
        node->mcastSender = DPS_MulticastStartSend(node);
    }
    node->netCtx = DPS_NetStart(node, rxPort, OnNetReceive);
    if (!node->netCtx) {
        DPS_ERRPRINT("Failed to initialize network context on port %d\n", rxPort);
        ret = DPS_ERR_NETWORK;
        goto ErrExit;
    }
    /*
     * Make sure have the listenting port before we return
     */
    node->port = DPS_NetGetListenerPort(node->netCtx);
    assert(node->port);
    /*
     *  The node loop gets its own thread to run on
     */
    r = uv_thread_create(&node->thread, NodeRun, node);
    if (r) {
        DPS_ERRPRINT("Failed to create node thread\n");
        ret = DPS_ERR_FAILURE;
        goto ErrExit;
    }
    return DPS_OK;

ErrExit:

    StopNode(node);
    return ret;

}

DPS_NetContext* DPS_GetNetContext(DPS_Node* node)
{
    return node->netCtx;
}

uv_loop_t* DPS_GetLoop(DPS_Node* node)
{
    return node->loop;
}

uint16_t DPS_GetPortNumber(DPS_Node* node)
{
    if (node) {
        return node->port;
    } else {
        return 0;
    }

}

static void StopNodeTask(DPS_Node* node)
{
    DPS_DBGTRACE();
    uv_stop(node->loop);
}

DPS_Status DPS_DestroyNode(DPS_Node* node, DPS_OnNodeDestroyed cb, void* data)
{
    DPS_DBGTRACE();
    if (!node || !cb) {
        return DPS_ERR_NULL;
    }
    if (node->state == DPS_NODE_STOPPING) {
        return DPS_ERR_INVALID;
    }
    if (!node->loop) {
        return DPS_OK;
    }
    DPS_LockNode(node);
    if (node->state == DPS_NODE_RUNNING) {
        node->state = DPS_NODE_STOPPING;
        node->onDestroyed = cb;
        node->onDestroyedData = data;
        node->tasks |= STOP_NODE_TASK;
        uv_async_send(&node->bgHandler);
        DPS_UnlockNode(node);
        return DPS_OK;
    }
    DPS_UnlockNode(node);
    assert(node->state == DPS_NODE_STOPPED);
    uv_mutex_destroy(&node->nodeMutex);
    free(node);
    return DPS_ERR_NODE_DESTROYED;
}

DPS_Status DPS_Link(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnLinkComplete cb, void* data)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = NULL;

    DPS_DBGTRACE();
    if (!addr || !node || !cb) {
        return DPS_ERR_NULL;
    }
    DPS_LockNode(node);
    ret = DPS_AddRemoteNode(node, addr, NULL, &remote);
    if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
        DPS_UnlockNode(node);
        return ret;
    }
    /*
     * Remote may already exist due to incoming data
     */
    if (remote->linked) {
        DPS_ERRPRINT("Node at %s already linked\n", DPS_NodeAddrToString(addr));
        DPS_UnlockNode(node);
        return ret;
    }
    /*
     * Operations must be serialized
     */
    if (remote->completion) {
        DPS_UnlockNode(node);
        return DPS_ERR_BUSY;
    }
    remote->linked = DPS_TRUE;
    remote->outbound.sync = DPS_TRUE;
    if (ret == DPS_OK) {
        remote->inbound.sync = DPS_TRUE;
    }
    remote->completion = AllocCompletion(node, remote, LINK_OP, data, LINK_RESPONSE_TIMEOUT, cb);
    if (!remote->completion) {
        DPS_DeleteRemoteNode(node, remote);
        DPS_UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    DPS_UnlockNode(node);
    DPS_UpdateSubs(node, remote);
    return DPS_OK;
}

DPS_Status DPS_Unlink(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnUnlinkComplete cb, void* data)
{
    RemoteNode* remote;

    DPS_DBGTRACE();
    if (!addr || !node || !cb) {
        return DPS_ERR_NULL;
    }
    DPS_LockNode(node);
    remote = DPS_LookupRemoteNode(node, addr);
    if (!remote || !remote->linked) {
        DPS_UnlockNode(node);
        return DPS_ERR_MISSING;
    }
    /*
     * Operations must be serialized
     */
    if (remote->completion) {
        DPS_UnlockNode(node);
        return DPS_ERR_BUSY;
    }
    /*
     * Unlinking the remote node will cause it to be deleted after the
     * subscriptions are updated. When the remote node is removed
     * the completion callback will be called.
     */
    remote->unlink = DPS_TRUE;
    remote->completion = AllocCompletion(node, remote, UNLINK_OP, data, LINK_RESPONSE_TIMEOUT, cb);
    if (!remote->completion) {
        DPS_DeleteRemoteNode(node, remote);
        DPS_UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    DPS_UnlockNode(node);
    DPS_UpdateSubs(node, remote);
    return DPS_OK;
}

static void RunBackgroundTasks(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    DPS_DBGTRACE();

    /*
     * TODO - may need to break some tasks into subtasks,
     * for example limit the number of subs or pubs on each
     * iteration so the node lock doesn't get held for too long.
     */
    DPS_LockNode(node);
    /*
     * The tasks are ordered according to priority
     */
    if (node->tasks & SEND_ACKS_TASK) {
        node->tasks &= ~SEND_ACKS_TASK;
        SendAcksTask(node);
    } else if (node->tasks & SEND_PUBS_TASK) {
        node->tasks &= ~SEND_PUBS_TASK;
        SendPubsTask(node);
    } else if (node->tasks & SEND_SUBS_TASK) {
        node->tasks &= ~SEND_SUBS_TASK;
        SendSubsTask(node);
    } else if (node->tasks & STOP_NODE_TASK) {
        node->tasks &= ~STOP_NODE_TASK;
        StopNodeTask(node);
    }
    if (node->tasks) {
        uv_async_send(&node->bgHandler);
    }
    DPS_UnlockNode(node);
}

const char* DPS_NodeAddrToString(DPS_NodeAddress* addr)
{
    return DPS_NetAddrText((struct sockaddr*)&addr->inaddr);
}

DPS_NodeAddress* DPS_CreateAddress()
{
    return calloc(1, sizeof(DPS_NodeAddress));
}

void DPS_CopyAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src)
{
    if (dest && src) {
        *dest = *src;
    }
}

void DPS_DestroyAddress(DPS_NodeAddress* addr)
{
    if (addr) {
        free(addr);
    }
}

void DPS_MakeNonce(const DPS_UUID* uuid, uint32_t seqNum, uint8_t msgType, uint8_t nonce[DPS_COSE_NONCE_SIZE])
{
    uint8_t* p = nonce;

    *p++ = (uint8_t)(seqNum >> 0);
    *p++ = (uint8_t)(seqNum >> 8);
    *p++ = (uint8_t)(seqNum >> 16);
    *p++ = (uint8_t)(seqNum >> 24);
    memcpy(p, uuid, DPS_COSE_NONCE_SIZE - sizeof(uint32_t));
    /*
     * Adjust one bit so nonce for PUB's and ACK's for same pub id and sequence number are different
     */
    if (msgType == DPS_MSG_TYPE_PUB) {
        p[0] &= 0x7F;
    } else {
        p[0] |= 0x80;
    }
}
