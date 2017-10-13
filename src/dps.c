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
#include <dps/private/cbor.h>
#include "coap.h"
#include "history.h"
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "ack.h"
#include "topics.h"
#include "linkmon.h"
#include "resolver.h"
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
    uint16_t ttl;
    uv_timer_t timer;
    union {
        DPS_OnLinkComplete link;
        DPS_OnUnlinkComplete unlink;
        void* cb;
    } on;
    struct _OnOpCompletion* next;
} OnOpCompletion;

/*
 * How long (in milliseconds) to wait to received a response from a remote
 * node this node is linking with.
 */
#define LINK_RESPONSE_TIMEOUT  5000

const DPS_UUID DPS_MaxMeshId = { .val64 = { UINT64_MAX, UINT64_MAX } };

void DPS_LockNode(DPS_Node* node)
{
    uv_thread_t self = uv_thread_self();
    if (node->lockCount && uv_thread_equal(&node->lockHolder, &self)) {
        ++node->lockCount;
    } else {
        uv_mutex_lock(&node->nodeMutex);
        assert(node->lockCount == 0);
        node->lockHolder = self;
        node->lockCount = 1;
    }
}

void DPS_UnlockNode(DPS_Node* node)
{
    assert(node->lockCount);
    if (--node->lockCount == 0) {
        uv_mutex_unlock(&node->nodeMutex);
    }
}

int DPS_HasNodeLock(DPS_Node* node)
{
    if (node->lockCount) {
        uv_thread_t self = uv_thread_self();
        return uv_thread_equal(&node->lockHolder, &self);
    } else {
        return DPS_FALSE;
    }
}

#define DESCRIBE(n)  DPS_NodeAddrToString(&(n)->ep.addr)

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
    if (memcpy_s(buffer->txPos, DPS_TxBufferSpace(buffer), data, len) != EOK) {
        return DPS_ERR_RESOURCES;
    }
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

    assert(DPS_HasNodeLock(node));
    /*
     * See AllocCompletion() timer.data is only set if the timer handle
     * was succesfully initialized
     */
    if (cpn->timer.data) {
        uv_timer_stop(&cpn->timer);
    }
    remote->completion = NULL;
    if (cpn->op == LINK_OP) {
        cpn->on.link(node, &addr, status, cpn->data);
    } else if (cpn->op == UNLINK_OP) {
        cpn->on.unlink(node, &addr, cpn->data);
    }
    if (cpn->timer.data) {
        uv_close((uv_handle_t*)&cpn->timer, OnTimerClosed);
    } else {
        free(cpn);
    }
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

static void FreeOutboundInterests(RemoteNode* remote)
{
    DPS_BitVectorFree(remote->outbound.interests);
    remote->outbound.interests = NULL;
    DPS_BitVectorFree(remote->outbound.needs);
    remote->outbound.needs = NULL;
}

DPS_Status DPS_ClearOutboundInterests(RemoteNode* remote)
{
    if (remote->outbound.interests) {
        DPS_BitVectorClear(remote->outbound.interests);
    } else {
        remote->outbound.interests = DPS_BitVectorAlloc();
    }
    if (remote->outbound.needs) {
        DPS_BitVectorClear(remote->outbound.needs);
    } else {
        remote->outbound.needs = DPS_BitVectorAllocFH();
    }
    if (!remote->outbound.interests || !remote->outbound.needs) {
        FreeOutboundInterests(remote);
        return DPS_ERR_RESOURCES;
    } else {
        return DPS_OK;
    }
}

void DPS_ClearInboundInterests(DPS_Node* node, RemoteNode* remote)
{
    if (remote->inbound.interests) {
        if (DPS_CountVectorDel(node->interests, remote->inbound.interests) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.interests);
        remote->inbound.interests = NULL;
    }
    if (remote->inbound.needs) {
        if (DPS_CountVectorDel(node->needs, remote->inbound.needs) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.needs);
        remote->inbound.needs = NULL;
    }
}

RemoteNode* DPS_DeleteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    RemoteNode* next;

    DPS_DBGTRACE();

    if (!IsValidRemoteNode(node, remote)) {
        return NULL;
    }
    if (remote->monitor) {
        DPS_LinkMonitorStop(remote);
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
    DPS_ClearInboundInterests(node, remote);
    FreeOutboundInterests(remote);
    DPS_BitVectorFree(remote->outbound.delta);

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

static const DPS_UUID* MinMeshId(DPS_Node* node, RemoteNode* excluded)
{
    RemoteNode* remote;
    DPS_UUID* minMeshId = &node->meshId;

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        if (remote->outbound.muted || remote->inbound.muted || remote == excluded) {
            continue;
        }
        if (DPS_UUIDCompare(&remote->inbound.meshId, minMeshId) < 0) {
            minMeshId = &remote->inbound.meshId;
        }
    }
    return minMeshId;
}

static DPS_Status UpdateOutboundInterests(DPS_Node* node, RemoteNode* destNode, int* send)
{
    DPS_Status ret;
    DPS_BitVector* newInterests = NULL;
    DPS_BitVector* newNeeds = NULL;

    DPS_DBGTRACE();

    /*
     * We don't update interests if we are muted but if we are
     * half-muted we need to send a subscription.
     */
    if (destNode->outbound.muted) {
        *send = !destNode->inbound.muted;
        return DPS_OK;
    }
    /*
     * Inbound interests from the node we are updating are excluded from the
     * recalculation of outbound interests
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
     * Send a delta if we have previously sent interests. The needs vector
     * is small so it is not worth computing a delta.
     */
    if (destNode->outbound.interests) {
        int same = DPS_FALSE;
        if (!destNode->outbound.delta) {
            destNode->outbound.delta = DPS_BitVectorAlloc();
            if (!destNode->outbound.delta) {
                ret = DPS_ERR_RESOURCES;
                goto ErrExit;
            }
        }
        DPS_BitVectorXor(destNode->outbound.delta, destNode->outbound.interests, newInterests, &same);
        if (same) {
            assert(DPS_BitVectorEquals(destNode->outbound.needs, newNeeds));
            *send = DPS_FALSE;
        } else {
            *send = DPS_TRUE;
        }
        destNode->outbound.deltaInd = DPS_TRUE;
    } else {
        /*
         * This is not a delta
         */
        destNode->outbound.deltaInd = DPS_FALSE;
        *send = DPS_TRUE;
    }
    FreeOutboundInterests(destNode);
    destNode->outbound.interests = newInterests;
    destNode->outbound.needs = newNeeds;
    /*
     * Increment the revision number if we are sending a subscription
     */
    if (*send) {
        /*
         * If there are interests we need to send our minimum
         * mesh id to enable loop detection. A routing loop
         * cannot exist without interests so we can just send
         * the maximum mesh id.
         */
        if (DPS_BitVectorIsClear(newInterests)) {
            destNode->outbound.meshId = DPS_MaxMeshId;
        } else {
            destNode->outbound.meshId = *(MinMeshId(node, destNode));
        }
        ++destNode->outbound.revision;
    }
    if (DPS_DEBUG_ENABLED() && *send) {
        DPS_DBGPRINT("New outbound interests for %s: ", DESCRIBE(destNode));
        DPS_DumpMatchingTopics(destNode->outbound.interests);
    }
    return DPS_OK;

ErrExit:
    DPS_ERRPRINT("UpdateOutboundInterests: %s\n", DPS_ErrTxt(ret));

    DPS_BitVectorFree(newInterests);
    DPS_BitVectorFree(newNeeds);
    return ret;
}

DPS_Status DPS_MuteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;

    assert(DPS_HasNodeLock(node));
    assert(!remote->outbound.muted);

    DPS_DBGPRINT("%d muting %s\n", node->port, DESCRIBE(remote));

    remote->outbound.muted = DPS_TRUE;
    remote->outbound.meshId = DPS_MaxMeshId;
    remote->inbound.meshId = DPS_MaxMeshId;
    /*
     * Clear the inbound and outbound interests
     */
    DPS_ClearInboundInterests(node, remote);
    ret = DPS_ClearOutboundInterests(remote);
    if (ret == DPS_OK) {
        /*
         * We are explicitly sending zero interests so not a delta
         */
        remote->outbound.deltaInd = DPS_FALSE;
        remote->outbound.ackCountdown = 0;
        ++remote->outbound.revision;
    }
    return ret;
}

DPS_Status DPS_UnmuteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    DPS_DBGTRACE();

    assert(DPS_HasNodeLock(node));
    assert(remote->outbound.muted);

    DPS_DBGPRINT("%d unmuting %s\n", node->port, DESCRIBE(remote));

    remote->outbound.muted = DPS_FALSE;
    remote->inbound.muted = DPS_FALSE;
    /*
     * Free stale outbound interests. This also ensures
     * that the first subscription sent after unmuting
     * is not a delta.
     */
    FreeOutboundInterests(remote);

    if (remote->monitor) {
        DPS_LinkMonitorStop(remote);
        /*
         * We need a fresh mesh id that is less than any of the mesh id's
         * we have already seen. If we were to send the same mesh id that
         * was used to detected the loop it will look to the remaining
         * nodes that there is still a loop.
         */
        DPS_RandUUIDLess(&node->minMeshId);
        node->meshId = node->minMeshId;
        DPS_UpdateSubs(node);
    }
    return DPS_OK;
}

int DPS_MeshHasLoop(DPS_Node* node, RemoteNode* src, DPS_UUID* meshId)
{
    if (DPS_UUIDCompare(meshId, &src->inbound.meshId) == 0) {
        return DPS_FALSE;
    } else {
        return DPS_UUIDCompare(meshId, MinMeshId(node, src)) == 0;
    }
}

RemoteNode* DPS_LookupRemoteNode(DPS_Node* node, DPS_NodeAddress* addr)
{
    RemoteNode* remote;

    assert(DPS_HasNodeLock(node));
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

static void AsyncCompletion(uv_async_t* async)
{
    DPS_Node* node = (DPS_Node*)async->data;

    DPS_DBGTRACE();

    DPS_LockNode(node);

    while (node->completionList) {
        OnOpCompletion* cpn = node->completionList;
        node->completionList = cpn->next;

        cpn->timer.data = NULL;
        if (node->state != DPS_NODE_RUNNING) {
            DPS_RemoteCompletion(node, cpn->remote, DPS_ERR_STOPPING);
            continue;
        }
        if (uv_timer_init(node->loop, &cpn->timer)) {
            DPS_RemoteCompletion(node, cpn->remote, DPS_ERR_FAILURE);
            continue;
        }
        /*
         * So cpn is freed when the timer handle is closed
         */
        cpn->timer.data = cpn;
        if (uv_timer_start(&cpn->timer, OnCompletionTimeout, cpn->ttl, 0)) {
            DPS_RemoteCompletion(node, cpn->remote, DPS_ERR_FAILURE);
            continue;
        }
    }

    DPS_UnlockNode(node);
}

static OnOpCompletion* AllocCompletion(DPS_Node* node, RemoteNode* remote, OpType op, void* data, uint16_t ttl, void* cb)
{
    OnOpCompletion* cpn;

    assert(DPS_HasNodeLock(node));

    cpn = calloc(1, sizeof(OnOpCompletion));
    if (cpn) {
        cpn->op = op;
        cpn->data = data;
        cpn->node = node;
        cpn->remote = remote;
        cpn->ttl = ttl;
        cpn->on.cb = cb;
        /*
         * We are holding the node lock so we can link the completion
         * after we have confirmed the async_send was successful.
         */
        if (uv_async_send(&node->completionAsync)) {
            free(cpn);
            cpn = NULL;
        } else {
            cpn->next = node->completionList;
            node->completionList = cpn;
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
    remote->inbound.meshId = DPS_MaxMeshId;
    remote->outbound.meshId = DPS_MaxMeshId;
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

static DPS_Status SendMatchingPubToSub(DPS_Node* node, DPS_Publication* pub, RemoteNode* subscriber)
{
    /*
     * We don't send publications to remote nodes we have received them from.
     */
    if (!DPS_PublicationReceivedFrom(&node->history, &pub->pubId, pub->sequenceNum, &pub->sender, &subscriber->ep.addr)) {
        /*
         * This is the pub/sub matching code
         */
        DPS_BitVectorIntersection(node->scratch.interests, pub->bf, subscriber->inbound.interests);
        DPS_BitVectorFuzzyHash(node->scratch.needs, node->scratch.interests);
        if (DPS_BitVectorIncludes(node->scratch.needs, subscriber->inbound.needs)) {
            DPS_DBGPRINT("Sending pub %d to %s\n", pub->sequenceNum, DESCRIBE(subscriber));
            return DPS_SendPublication(node, pub, subscriber);
        }
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->sequenceNum, DESCRIBE(subscriber));
    }
    return DPS_OK;
}

static void SendAcksTask(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;
    PublicationAck* ack;

    DPS_DBGTRACE();

    DPS_LockNode(node);
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
    DPS_UnlockNode(node);
}

static void SendPubsTask(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_Publication* pub;
    DPS_Publication* nextPub;

    DPS_DBGTRACE();

    DPS_LockNode(node);
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
                ret = DPS_SendPublication(node, pub, NULL);
                if (ret != DPS_OK) {
                    DPS_ERRPRINT("SendPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
                }
            }
            for (remote = node->remoteNodes; remote != NULL; remote = nextRemote) {
                nextRemote = remote->next;
                if (!(remote->outbound.muted || remote->inbound.muted) && remote->inbound.interests) {
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
    DPS_UnlockNode(node);
}

static void SendSubsTimer(uv_timer_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_Status ret = DPS_OK;
    RemoteNode* remote;
    RemoteNode* remoteNext;
    int reschedule = DPS_FALSE;

    DPS_DBGTRACE();

    DPS_LockNode(node);
    /*
     * Forward subscription to all remote nodes with interests
     */
    for (remote = node->remoteNodes; remote != NULL; remote = remoteNext) {
        int send = DPS_FALSE;
        remoteNext = remote->next;

        if (remote->unlink) {
            reschedule = DPS_TRUE;
            DPS_SendSubscription(node, remote);
            DPS_DBGPRINT("Remote node has been unlinked - deleting\n");
            DPS_DeleteRemoteNode(node, remote);
            continue;
        }
        /*
         * Resend the previous subscription if it has not been ACK'd
         */
        if (remote->outbound.ackCountdown) {
            if (remote->outbound.ackCountdown == 1) {
                DPS_WARNPRINT("Reached retry limit - deleting unresponsive remote %s\n", DESCRIBE(remote));
                DPS_DeleteRemoteNode(node, remote);
                /*
                 * Eat the error and continue
                 */
                ret = DPS_OK;
                continue;
            }
            /*
             * We don't start resending until we hit the retry threshold
             */
            if (remote->outbound.ackCountdown > DPS_MAX_SUBSCRIPTION_RETRIES) {
                reschedule = DPS_TRUE;
                --remote->outbound.ackCountdown;
                continue;
            }
            send = DPS_TRUE;
        } else {
            ret = UpdateOutboundInterests(node, remote, &send);
            if (ret != DPS_OK) {
                break;
            }
        }
        if (send) {
            reschedule = DPS_TRUE;
            ret = DPS_SendSubscription(node, remote);
            if (ret != DPS_OK) {
                DPS_DeleteRemoteNode(node, remote);
                DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
                /*
                 * Eat the error and continue
                 */
                ret = DPS_OK;
            }
        }
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("SendSubsTask failed %s\n", DPS_ErrTxt(ret));
    }
    if (reschedule) {
        node->subsPending = DPS_TRUE;
        uv_timer_start(&node->subsTimer, SendSubsTimer, node->subsRate, 0);
    } else {
        node->subsPending = DPS_FALSE;
    }
    DPS_UnlockNode(node);
}

static void SendSubsTask(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    DPS_LockNode(node);
    if (node->state == DPS_NODE_RUNNING) {
        node->subsPending = DPS_TRUE;
        uv_timer_start(&node->subsTimer, SendSubsTimer, 0, 0);
    }
    DPS_UnlockNode(node);
}

/*
 * Run checks of one or more publications against the current subscriptions
 */
void DPS_UpdatePubs(DPS_Node* node, DPS_Publication* pub)
{
    int count = 0;
    DPS_DBGTRACE();

    DPS_LockNode(node);
    if (node->state != DPS_NODE_RUNNING) {
        DPS_UnlockNode(node);
        return;
    }

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
        uv_async_send(&node->pubsAsync);
    }
    DPS_UnlockNode(node);
}

void DPS_UpdateSubs(DPS_Node* node)
{
    DPS_LockNode(node);
    if ((node->state == DPS_NODE_RUNNING) && !node->subsPending) {
        uv_async_send(&node->subsAsync);
    }
    DPS_UnlockNode(node);
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
    uv_async_send(&node->acksAsync);
    DPS_UnlockNode(node);
}

static DPS_Status DecodeRequest(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buf, int multicast)
{
    DPS_Status ret;
    uint8_t msgVersion;
    uint8_t msgType;
    size_t len;

    DPS_DBGTRACE();
    CBOR_Dump("Request in", buf->rxPos, DPS_RxBufferAvail(buf));
    ret = CBOR_DecodeArray(buf, &len);
    if (ret != DPS_OK || (len != 5)) {
        DPS_ERRPRINT("Expected a CBOR array of 5 elements\n");
        return ret;
    }
    ret = CBOR_DecodeUint8(buf, &msgVersion);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Expected a message type\n");
        return ret;
    }
    if (msgVersion != DPS_MSG_VERSION) {
        DPS_ERRPRINT("Expected message version %d, received %d\n", DPS_MSG_VERSION, msgVersion);
        return DPS_ERR_NOT_IMPLEMENTED;
    }
    ret = CBOR_DecodeUint8(buf, &msgType);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Expected a message type\n");
        return ret;
    }
    ret = DPS_ERR_INVALID;
    switch (msgType) {
    case DPS_MSG_TYPE_SUB:
        ret = DPS_DecodeSubscription(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscription returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_PUB:
        DPS_DBGPRINT("Received publication via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DPS_DecodePublication(node, ep, buf, multicast);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublication returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_ACK:
        DPS_DBGPRINT("Received acknowledgment via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DPS_DecodeAcknowledgment(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DPS_DecodeAcknowledgment returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_SAK:
        DPS_DBGPRINT("Received sub ack via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DPS_DecodeSubscriptionAck(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DPS_DecodeSubscriptionAck returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    default:
        DPS_ERRPRINT("Invalid message type\n");
        break;
    }
    /*
     * Stale is not a network or invalid message error, so don't
     * report an error to the transport.
     */
    if (ret == DPS_ERR_STALE) {
        ret = DPS_OK;
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
    DPS_LockNode(node);
    if (node->state != DPS_NODE_RUNNING) {
        DPS_UnlockNode(node);
        return DPS_ERR_FAILURE;
    }
    DPS_UnlockNode(node);
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
    DPS_LockNode(node);
    if (node->state != DPS_NODE_RUNNING) {
        DPS_UnlockNode(node);
        return DPS_ERR_FAILURE;
    }
    DPS_UnlockNode(node);
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
    assert(!uv_is_closing((uv_handle_t*)&node->stopAsync));
    uv_close((uv_handle_t*)&node->stopAsync, NULL);
    uv_close((uv_handle_t*)&node->pubsAsync, NULL);
    uv_close((uv_handle_t*)&node->subsAsync, NULL);
    uv_close((uv_handle_t*)&node->acksAsync, NULL);
    uv_close((uv_handle_t*)&node->subsTimer, NULL);
    /*
     * Cleanup any unresolved resolvers before closing the handle
     */
    DPS_AsyncResolveAddress(&node->resolverAsync);
    uv_close((uv_handle_t*)&node->resolverAsync, NULL);
    /*
     * Cancel any pending completions before closing the handle
     */
    AsyncCompletion(&node->completionAsync);
    uv_close((uv_handle_t*)&node->completionAsync, NULL);
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
    node->loop = NULL;
}

static void NodeRun(void* arg)
{
    int r;
    DPS_Node* node = (DPS_Node*)arg;
    uv_thread_t thisThread = node->thread;

    uv_run(node->loop, UV_RUN_DEFAULT);

    DPS_DBGPRINT("Stopping node\n");

    DPS_LockNode(node);
    StopNode(node);
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

    DPS_DBGPRINT("Exiting node thread\n");

    /*
     * Note: this is not currently a libuv API and is implemented locally
     */
    r = uv_thread_detach(&thisThread);
    if (r) {
        DPS_ERRPRINT("Failed to detatch thread: %s\n", uv_err_name(r));
    }
}


DPS_Node* DPS_CreateNode(const char* separators, DPS_KeyStore* keyStore, const DPS_UUID* keyId)
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
    /*
     * Sanity check
     */
    if (keyId && (!keyStore || !keyStore->keyHandler)) {
        DPS_ERRPRINT("A key request callback is required\n");
        free(node);
        return NULL;
    }
    if (keyId || (keyStore && keyStore->keyHandler)) {
        node->isSecured = DPS_TRUE;
        memcpy_s(&node->keyId, sizeof(DPS_UUID), keyId, sizeof(DPS_UUID));
    }
    strncpy_s(node->separators, sizeof(node->separators), separators, sizeof(node->separators) - 1);
    node->keyStore = keyStore;
    /*
     * Set default probe configuration and subscription rate parameters
     */
    node->linkMonitorConfig = LinkMonitorConfigDefaults;
    node->subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
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
    return node ? node->userData : NULL;
}

static void StopNodeTask(uv_async_t* handle)
{
    DPS_DBGTRACE();
    /*
     * Stopping the loop will cleanly stop the node
     */
    uv_stop(handle->loop);
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
     * Setup the asyncs for running background tasks
     */
    node->acksAsync.data = node;
    r = uv_async_init(node->loop, &node->acksAsync, SendAcksTask);
    assert(!r);

    node->pubsAsync.data = node;
    r = uv_async_init(node->loop, &node->pubsAsync, SendPubsTask);
    assert(!r);

    node->subsAsync.data = node;
    r = uv_async_init(node->loop, &node->subsAsync, SendSubsTask);
    assert(!r);

    node->stopAsync.data = node;
    r = uv_async_init(node->loop, &node->stopAsync, StopNodeTask);
    assert(!r);

    node->resolverAsync.data = node;
    r = uv_async_init(node->loop, &node->resolverAsync, DPS_AsyncResolveAddress);
    assert(!r);

    node->completionAsync.data = node;
    r = uv_async_init(node->loop, &node->completionAsync, AsyncCompletion);
    assert(!r);

    node->subsTimer.data = node;
    r = uv_timer_init(node->loop, &node->subsTimer);
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

    node->meshId = DPS_MaxMeshId;
    node->minMeshId = DPS_MaxMeshId;

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
    node->state = DPS_NODE_RUNNING;
    return DPS_OK;

ErrExit:

    DPS_LockNode(node);
    StopNode(node);
    DPS_UnlockNode(node);
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

DPS_Status DPS_DestroyNode(DPS_Node* node, DPS_OnNodeDestroyed cb, void* data)
{
    DPS_DBGTRACE();
    if (!node || !cb) {
        return DPS_ERR_NULL;
    }
    if (node->state == DPS_NODE_STOPPING) {
        return DPS_ERR_INVALID;
    }
    /*
     * Node might be destroyed before it was started
     */
    if (node->state != DPS_NODE_CREATED) {
        DPS_LockNode(node);
        if (node->state == DPS_NODE_RUNNING) {
            node->state = DPS_NODE_STOPPING;
            node->onDestroyed = cb;
            node->onDestroyedData = data;
            uv_async_send(&node->stopAsync);
            DPS_UnlockNode(node);
            return DPS_OK;
        }
        DPS_UnlockNode(node);
        assert(node->state == DPS_NODE_STOPPED);
        uv_mutex_destroy(&node->nodeMutex);
    }
    free(node);
    return DPS_ERR_NODE_DESTROYED;
}

void DPS_SetNodeSubscriptionUpdateDelay(DPS_Node* node, uint32_t subsRateMsecs)
{
    node->subsRate = subsRateMsecs;
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
     * Remote may already exist due to incoming data which is ok,
     * but if we already linked it we return an error.
     */
    if (remote->linked) {
        DPS_ERRPRINT("Node at %s already linked\n", DPS_NodeAddrToString(addr));
        DPS_UnlockNode(node);
        return DPS_ERR_EXISTS;
    }
    assert(!remote->completion);
    remote->linked = DPS_TRUE;
    remote->completion = AllocCompletion(node, remote, LINK_OP, data, LINK_RESPONSE_TIMEOUT, cb);
    if (!remote->completion) {
        DPS_DeleteRemoteNode(node, remote);
        DPS_UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    DPS_UnlockNode(node);
    /*
     * This will cause an initial subscription to be sent to the remote node
     */
    DPS_UpdateSubs(node);
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
     * We need to unmute the remote to send the unlink subscription
     */
    remote->outbound.muted = DPS_FALSE;
    remote->inbound.muted = DPS_FALSE;
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
    DPS_UpdateSubs(node);
    return DPS_OK;
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
    memcpy_s(p, DPS_COSE_NONCE_SIZE - sizeof(uint32_t), uuid, DPS_COSE_NONCE_SIZE - sizeof(uint32_t));
    /*
     * Adjust one bit so nonce for PUB's and ACK's for same pub id and sequence number are different
     */
    if (msgType == DPS_MSG_TYPE_PUB) {
        p[0] &= 0x7F;
    } else {
        p[0] |= 0x80;
    }
}

static DPS_Status SetKey(DPS_KeyStoreRequest* request, const unsigned char* key, size_t len)
{
    if (len > AES_128_KEY_LEN) {
        DPS_ERRPRINT("Key has size %d, but only %d buffer\n", len, AES_128_KEY_LEN);
        return DPS_ERR_MISSING;
    }
    memcpy(request->data, key, len);
    return DPS_OK;
}

DPS_Status DPS_GetCOSEKey(void* ctx, const DPS_UUID* kid, int8_t alg, uint8_t key[AES_128_KEY_LEN])
{
    DPS_Node* node = (DPS_Node*)ctx;
    DPS_KeyStore* keyStore = node->keyStore;
    DPS_KeyStoreRequest request;

    request.keyStore = keyStore;
    request.data = key;
    request.setKey = SetKey;
    return keyStore->keyHandler(&request, (const unsigned char*)kid, sizeof(DPS_UUID));
}
