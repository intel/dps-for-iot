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
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include "node.h"
#include "bitvec.h"
#include "cbor.h"
#include "sub.h"
#include "pub.h"
#include "topics.h"
#include "node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static int IsValidSub(const DPS_Subscription* sub)
{
    DPS_Subscription* subList;

    if (!sub || !sub->node || !sub->node->loop) {
        return DPS_FALSE;
    }
    DPS_LockNode(sub->node);
    for (subList = sub->node->subscriptions; subList != NULL; subList = subList->next) {
        if (sub == subList) {
            break;
        }
    }
    DPS_UnlockNode(sub->node);
    return subList != NULL;
}

size_t DPS_SubscriptionGetNumTopics(const DPS_Subscription* sub)
{
    return IsValidSub(sub) ? sub->numTopics : 0;
}

const char* DPS_SubscriptionGetTopic(const DPS_Subscription* sub, size_t index)
{
    if (IsValidSub(sub) && (sub->numTopics > index)) {
        return sub->topics[index];
    } else {
        return NULL;
    }
}

static DPS_Subscription* FreeSubscription(DPS_Subscription* sub)
{
    DPS_Subscription* next = sub->next;
    DPS_BitVectorFree(sub->bf);
    DPS_BitVectorFree(sub->needs);
    while (sub->numTopics) {
        free(sub->topics[--sub->numTopics]);
    }
    free(sub);
    return next;
}

void DPS_FreeSubscriptions(DPS_Node* node)
{
    while (node->subscriptions) {
        node->subscriptions = FreeSubscription(node->subscriptions);
    }
}

DPS_Subscription* DPS_CreateSubscription(DPS_Node* node, const char** topics, size_t numTopics)
{
    size_t i;
    DPS_Subscription* sub;

    if (!node || !topics || !numTopics) {
        return NULL;
    }
    sub = calloc(1, sizeof(DPS_Subscription) + sizeof(char*) * (numTopics - 1));
    /*
     * Add the topics to the subscription
     */
    for (i = 0; i < numTopics; ++i) {
        size_t len = strlen(topics[i]);
        sub->topics[i] = malloc(len + 1);
        if (!sub->topics[i]) {
            FreeSubscription(sub);
            return NULL;
        }
        ++sub->numTopics;
        memcpy(sub->topics[i], topics[i], len + 1);
    }
    sub->node = node;
    return sub;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_Node* node;

    if (!IsValidSub(sub)) {
        return DPS_ERR_MISSING;
    }
    node = sub->node;
    /*
     * Protect the node while we update it
     */
    DPS_LockNode(node);
    /*
     * Unlink the subscription
     */
    if (node->subscriptions == sub) {
        node->subscriptions = sub->next;
    } else {
        DPS_Subscription* prev = node->subscriptions;
        while (prev->next != sub) {
            prev = prev->next;
        }
        prev->next = sub->next;
    }
    /*
     * This remove this subscriptions contributions to the interests and needs
     */
    if (DPS_CountVectorDel(node->interests, sub->bf) != DPS_OK) {
        assert(!"Count error");
    }
    if (DPS_CountVectorDel(node->needs, sub->needs) != DPS_OK) {
        assert(!"Count error");
    }
    DPS_UnlockNode(node);

    DPS_DBGPRINT("Unsubscribing from %zu topics\n", sub->numTopics);
    FreeSubscription(sub);

    DPS_UpdateSubs(node, NULL);

    return DPS_OK;
}

DPS_Status DPS_SendSubscription(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, uint16_t ttl)
{
    DPS_Status ret;
    DPS_Buffer payload;
    DPS_BitVector* needs = remote->outbound.needs;

    size_t allocSize = DPS_BitVectorSerializeMaxSize(needs) + DPS_BitVectorSerializeMaxSize(interests) + 40;

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
    ret = DPS_BufferInit(&payload, NULL, allocSize);
    if (ret != DPS_OK) {
        return ret;
    }
    CBOR_EncodeUint8(&payload, DPS_MSG_TYPE_SUB);
    /*
     * Write listening port
     */
    CBOR_EncodeUint16(&payload, node->port);
    CBOR_EncodeUint16(&payload, ttl);
    CBOR_EncodeBoolean(&payload, remote->inbound.sync);
    CBOR_EncodeBoolean(&payload, remote->outbound.sync);
    ret = DPS_BitVectorSerialize(needs, &payload);
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(interests, &payload);
    }
    if (ret == DPS_OK) {
        uv_buf_t bufs[] = {
            { (char*)payload.base, DPS_BufferUsed(&payload) }
        };
        ret = DPS_NetSend(node, &remote->ep, bufs, A_SIZEOF(bufs), DPS_OnSendComplete);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
            DPS_SendFailed(node, &remote->ep.addr, bufs, A_SIZEOF(bufs), ret);
        }
    } else {
        free(payload.base);
        return ret;
    }
    /*
     * Done with these flags
     */
    remote->inbound.sync = DPS_FALSE;
    remote->outbound.sync = DPS_FALSE;
    return ret;
}

/*
 * Unsubscribes this node from a remote node by sending a cleared bit vector
 */
DPS_Status DPS_SendUnsubscribe(DPS_Node* node, RemoteNode* remote)
{
    if (remote->outbound.interests) {
        DPS_BitVectorClear(remote->outbound.interests);
        DPS_BitVectorClear(remote->outbound.needs);
    } else {
        remote->outbound.interests = DPS_BitVectorAlloc();
        remote->outbound.needs = DPS_BitVectorAllocFH();
        if (!remote->outbound.interests || !remote->outbound.needs) {
            DPS_BitVectorFree(remote->outbound.interests);
            DPS_BitVectorFree(remote->outbound.needs);
            return DPS_ERR_RESOURCES;
        }
    }
    remote->inbound.sync = DPS_FALSE;
    remote->outbound.sync = DPS_TRUE;
    return DPS_SendSubscription(node, remote, remote->outbound.interests, 0);
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs, int delta)
{
    DPS_DBGTRACE();

    if (remote->inbound.interests) {
        if (delta) {
            DPS_DBGPRINT("Received interests delta\n");
            DPS_BitVectorXor(interests, interests, remote->inbound.interests, NULL);
        }
        DPS_CountVectorDel(node->interests, remote->inbound.interests);
        DPS_CountVectorDel(node->needs, remote->inbound.needs);
        DPS_BitVectorFree(remote->inbound.interests);
        remote->inbound.interests = NULL;
        DPS_BitVectorFree(remote->inbound.needs);
        remote->inbound.needs = NULL;
        remote->inbound.updates = DPS_TRUE;
    }
    if (DPS_BitVectorIsClear(interests)) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    } else {
        DPS_CountVectorAdd(node->interests, interests);
        DPS_CountVectorAdd(node->needs, needs);
        remote->inbound.interests = interests;
        remote->inbound.needs = needs;
        remote->inbound.updates = DPS_TRUE;
    }
    return DPS_OK;
}

/*
 *
 */
DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    uint16_t port;
    uint16_t ttl;
    RemoteNode* remote;
    int syncRequested;
    int syncReceived;

    DPS_DBGTRACE();

    interests = DPS_BitVectorAlloc();
    if (!interests) {
        return DPS_ERR_RESOURCES;
    }
    needs = DPS_BitVectorAllocFH();
    if (!needs) {
        DPS_BitVectorFree(interests);
        return DPS_ERR_RESOURCES;
    }
    ret = CBOR_DecodeUint16(buffer, &port);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_EndpointSetPort(ep, port);
    ret = CBOR_DecodeUint16(buffer, &ttl);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_DBGPRINT("TTL=%d\n", ttl);
    ret = CBOR_DecodeBoolean(buffer, &syncRequested);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBoolean(buffer, &syncReceived);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_BitVectorDeserialize(needs, buffer);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_BitVectorDeserialize(interests, buffer);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_LockNode(node);
    ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, ttl, &remote);
    DPS_UnlockNode(node);
    if (ret != DPS_OK) {
        if (ret != DPS_ERR_EXISTS) {
            DPS_BitVectorFree(interests);
            DPS_BitVectorFree(needs);
            return ret;
        }
        ret = DPS_OK;
    } else {
        /*
         * The remote is new to us so we need to synchronize even if the remote
         * didn't request to.
         */
        syncRequested = DPS_TRUE;
    }
    DPS_LockNode(node);
    if (ttl == 0) {
        DPS_DeleteRemoteNode(node, remote);
    } else {
        if (syncRequested) {
            remote->outbound.sync = DPS_TRUE;
        }
        ret = UpdateInboundInterests(node, remote, interests, needs, !syncReceived);
        /*
         * Check if application waiting for a completion callback
         */
        if (remote->completion) {
            DPS_RemoteCompletion(node, remote, DPS_OK);
        }
    }
    DPS_UnlockNode(node);
    /*
     * Schedule background tasks
     */
    if (ret == DPS_OK) {
        DPS_UpdatePubs(node, NULL);
        DPS_UpdateSubs(node, NULL);
    }
    return ret;
}

DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler)
{
    size_t i;
    DPS_Status ret = DPS_OK;
    DPS_Node* node = sub ? sub->node : NULL;

    if (!node) {
        return DPS_ERR_NULL;
    }
    if (!node->loop) {
        return DPS_ERR_NOT_STARTED;
    }
    sub->handler = handler;
    sub->bf = DPS_BitVectorAlloc();
    sub->needs = DPS_BitVectorAllocFH();
    if (!sub->bf || !sub->needs) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Add the topics to the bloom filter
     */
    for (i = 0; i < sub->numTopics; ++i) {
        ret = DPS_AddTopic(sub->bf, sub->topics[i], node->separators, DPS_SubTopic);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        return ret;
    }

    DPS_DBGPRINT("Subscribing to %zu topics\n", sub->numTopics);
    DPS_DumpTopics((const char**)sub->topics, sub->numTopics);

    DPS_BitVectorFuzzyHash(sub->needs, sub->bf);
    /*
     * Protect the node while we update it
     */
    DPS_LockNode(node);
    sub->next = node->subscriptions;
    node->subscriptions = sub;
    ret = DPS_CountVectorAdd(node->interests, sub->bf);
    if (ret == DPS_OK) {
        ret = DPS_CountVectorAdd(node->needs, sub->needs);
    }
    DPS_UnlockNode(node);
    if (ret == DPS_OK) {
        DPS_UpdateSubs(node, NULL);
    }
    return ret;
}

DPS_Status DPS_SetSubscriptionData(DPS_Subscription* sub, void* data)
{
    if (sub) {
        sub->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetSubscriptionData(DPS_Subscription* sub)
{
    return sub ? sub->userData : NULL;
}

void DPS_DumpSubscriptions(DPS_Node* node)
{
    DPS_Subscription* sub;

    DPS_DBGPRINT("Current subscriptions:\n");
    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        DPS_DumpTopics((const char**)sub->topics, sub->numTopics);
    }
}
