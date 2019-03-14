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
#include <safe_lib.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/cbor.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include <dps/uuid.h>
#include "bitvec.h"
#include "compat.h"
#include "linkmon.h"
#include "node.h"
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "topics.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Set to non-zero value to simulate lost subscriptions
 * and subscription acknowledgements
 *
 * Value N specifies rate of loss 1/N
 */
#ifndef SIMULATE_PACKET_LOSS
#define SIMULATE_PACKET_LOSS 0
#endif

#define DESCRIBE(n)  DPS_NodeAddrToString(&(n)->ep.addr)

#define DPS_SUB_FLAG_DELTA_IND  0x01      /* Indicate interests is a delta */
#define DPS_SUB_FLAG_MUTE_IND   0x02      /* Mute has been indicated */

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

DPS_Node* DPS_SubscriptionGetNode(const DPS_Subscription* sub)
{
    if (IsValidSub(sub)) {
        return sub->node;
    } else {
        return NULL;
    }
}

static DPS_Subscription* FreeSubscription(DPS_Subscription* sub)
{
    DPS_Node* node = sub->node;
    DPS_Subscription* next = sub->next;
    int unlinked = DPS_FALSE;

    if (!(sub->flags & SUB_FLAG_WAS_FREED)) {
        /*
         * Unlink the subscription
         */
        if (node->subscriptions == sub) {
            node->subscriptions = sub->next;
            unlinked = DPS_TRUE;
        } else {
            DPS_Subscription* prev = node->subscriptions;
            while (prev && (prev->next != sub)) {
                prev = prev->next;
            }
            if (prev && (prev->next == sub)) {
                prev->next = sub->next;
                unlinked = DPS_TRUE;
            }
        }
        /*
         * This removes this subscription's contributions to the interests and needs
         */
        if (unlinked) {
            if (DPS_CountVectorDel(node->interests, sub->bf) != DPS_OK) {
                assert(!"Count error");
            }
            if (DPS_CountVectorDel(node->needs, sub->needs) != DPS_OK) {
                assert(!"Count error");
            }
        }
        sub->next = NULL;
        sub->flags = SUB_FLAG_WAS_FREED;
    }

    if (sub->refCount == 0) {
        DPS_BitVectorFree(sub->bf);
        DPS_BitVectorFree(sub->needs);
        while (sub->numTopics) {
            free(sub->topics[--sub->numTopics]);
        }
        free(sub);
    }

    return next;
}

void DPS_SubscriptionIncRef(DPS_Subscription* sub)
{
    ++sub->refCount;
}

void DPS_SubscriptionDecRef(DPS_Subscription* sub)
{
    assert(sub->refCount != 0);
    if ((--sub->refCount == 0) && (sub->flags & SUB_FLAG_WAS_FREED)) {
        FreeSubscription(sub);
    }
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

    DPS_DBGTRACE();

    if (!node || !topics || !numTopics) {
        return NULL;
    }
    sub = calloc(1, sizeof(DPS_Subscription) + sizeof(char*) * (numTopics - 1));
    /*
     * Add the topics to the subscription
     */
    for (i = 0; i < numTopics; ++i) {
        sub->topics[i] = strndup(topics[i], DPS_MAX_TOPIC_STRLEN);
        if (!sub->topics[i]) {
            FreeSubscription(sub);
            return NULL;
        }
        ++sub->numTopics;
    }
    sub->node = node;
    return sub;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_Node* node;

    DPS_DBGTRACE();

    if (!IsValidSub(sub)) {
        return DPS_ERR_MISSING;
    }
    node = sub->node;
    /*
     * Protect the node while we update it
     */
    DPS_LockNode(node);
    DPS_DBGPRINT("Unsubscribing from %zu topics\n", sub->numTopics);
    FreeSubscription(sub);
    DPS_UnlockNode(node);

    DPS_UpdateSubs(node);

    return DPS_OK;
}

#ifdef DPS_DEBUG
int _DPS_NumSubs = 0;
#endif

DPS_Status DPS_SendSubscription(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    DPS_BitVector* interests;
    size_t len;
    uint8_t flags = 0;

    DPS_DBGTRACE();

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
#ifdef DPS_DEBUG
    ++_DPS_NumSubs;
#endif
    /*
     * Set flags
     */
    if (remote->outbound.deltaInd) {
        flags |= DPS_SUB_FLAG_DELTA_IND;
    }
    if (remote->outbound.muted) {
        flags |= DPS_SUB_FLAG_MUTE_IND;
    }

    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
           CBOR_SIZEOF(uint32_t);  /* seq_num */
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        len += CBOR_SIZEOF(uint16_t); /* port */
        break;
    case DPS_PIPE:
        len += CBOR_SIZEOF_STRING(node->addr.u.path); /* path */
        break;
    default:
        return DPS_ERR_INVALID;
    }
    if (!remote->unlink) {
        interests = remote->outbound.deltaInd ? remote->outbound.delta : remote->outbound.interests;
        len += 4 * CBOR_SIZEOF(uint8_t) +
               CBOR_SIZEOF(uint8_t) +
               CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
               DPS_BitVectorSerializeMaxSize(interests) +
               DPS_BitVectorSerializeFHSize();

    } else {
        interests = NULL;
    }
    /*
     * The protected and encrypted maps
     */
    len += CBOR_SIZEOF_MAP(0) +
        CBOR_SIZEOF_MAP(0);

    ret = DPS_TxBufferInit(&buf, NULL, len);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_SUB);
    }
    /*
     * Encode the unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, remote->unlink ? 2 : 6);
    }
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint16(&buf,
                                    DPS_NetAddrPort((const struct sockaddr*)&node->addr.u.inaddr));
        }
        break;
    default:
        break;
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        /*
         * See DPS_UpdateOutboundInterests() the outbound sequence number
         * only changes if the subscription changes.
         */
        ret = CBOR_EncodeUint32(&buf, remote->outbound.revision);
    }
    if (!remote->unlink) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SUB_FLAGS);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, flags);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_MESH_ID);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeBytes(&buf, (uint8_t*)&remote->outbound.meshId, sizeof(DPS_UUID));
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_NEEDS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerializeFH(remote->outbound.needs, &buf);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_INTERESTS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(interests, &buf);
        }
    }
    switch (node->addr.type) {
    case DPS_PIPE:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PATH);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeString(&buf, node->addr.u.path);
        }
        break;
    default:
        break;
    }
    /*
     * Encode the (empty) protected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    /*
     * Encode the (empty) encrypted map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }

    if (ret == DPS_OK) {
        uv_buf_t uvBuf = uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf));
        CBOR_Dump("Sub out", (uint8_t*)uvBuf.base, uvBuf.len);
        ret = DPS_NetSend(node, NULL, &remote->ep, &uvBuf, 1, DPS_OnSendSubscriptionComplete);
        if (ret == DPS_OK) {
            remote->outbound.subPending = DPS_TRUE;
            if (remote->outbound.ackCountdown) {
                --remote->outbound.ackCountdown;
            } else {
                remote->outbound.ackCountdown = 1 + DPS_MAX_SUBSCRIPTION_RETRIES;
            }
            assert(remote->outbound.ackCountdown);
        } else {
            DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
            DPS_SendComplete(node, &remote->ep.addr, &uvBuf, 1, ret);
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

static DPS_Status SendSubscriptionAck(DPS_Node* node, RemoteNode* remote, uint32_t revision, int includeSub)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    DPS_BitVector* interests;
    size_t len;
    uint8_t flags = 0;

    DPS_DBGTRACE();

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    /*
     * Set flags
     */
    if (remote->outbound.deltaInd) {
        flags |= DPS_SUB_FLAG_DELTA_IND;
    }
    if (remote->outbound.muted) {
        flags |= DPS_SUB_FLAG_MUTE_IND;
    }

    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint32_t);  /* ack_seq_num */
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        len += CBOR_SIZEOF(uint16_t); /* port */
        break;
    case DPS_PIPE:
        len += CBOR_SIZEOF_STRING(node->addr.u.path); /* path */
        break;
    default:
        return DPS_ERR_INVALID;
    }
    if (includeSub) {
        len += CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint32_t);
        interests = remote->outbound.deltaInd ? remote->outbound.delta : remote->outbound.interests;
        len += 4 * CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
            DPS_BitVectorSerializeMaxSize(interests) +
            DPS_BitVectorSerializeMaxSize(remote->outbound.needs);
    } else {
        interests = NULL;
    }
    /*
     * The protected and encrypted maps
     */
    len += CBOR_SIZEOF_MAP(0) +
        CBOR_SIZEOF_MAP(0);

    ret = DPS_TxBufferInit(&buf, NULL, len);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_SAK);
    }
    /*
     * Encode the unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, includeSub ? 7 : 2);
    }
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint16(&buf,
                                    DPS_NetAddrPort((const struct sockaddr*)&node->addr.u.inaddr));
        }
        break;
    default:
        break;
    }
    if (includeSub) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SEQ_NUM);
        }
        if (ret == DPS_OK) {
            /*
             * See DPS_UpdateOutboundInterests() the outbound sequence number
             * only changes if the subscription changes.
             */
            ret = CBOR_EncodeUint32(&buf, remote->outbound.revision);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SUB_FLAGS);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, flags);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_MESH_ID);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeBytes(&buf, (uint8_t*)&remote->outbound.meshId, sizeof(DPS_UUID));
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_NEEDS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerializeFH(remote->outbound.needs, &buf);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_INTERESTS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(interests, &buf);
        }
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_ACK_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&buf, revision);
    }
    switch (node->addr.type) {
    case DPS_PIPE:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PATH);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeString(&buf, node->addr.u.path);
        }
        break;
    default:
        break;
    }
    /*
     * Encode the (empty) protected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    /*
     * Encode the (empty) encrypted map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }

    if (ret == DPS_OK) {
        uv_buf_t uvBuf = uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf));
        CBOR_Dump("Sub ack out", (uint8_t*)uvBuf.base, uvBuf.len);
        ret = DPS_NetSend(node, NULL, &remote->ep, &uvBuf, 1, DPS_OnSendComplete);
        if (ret == DPS_OK) {
            if (includeSub) {
                remote->outbound.subPending = DPS_TRUE;
                if (remote->outbound.ackCountdown) {
                    --remote->outbound.ackCountdown;
                } else {
                    remote->outbound.ackCountdown = 1 + DPS_MAX_SUBSCRIPTION_RETRIES;
                }
                assert(remote->outbound.ackCountdown);
            }
        } else {
            DPS_ERRPRINT("Failed to send subscription ack %s\n", DPS_ErrTxt(ret));
            DPS_SendComplete(node, &remote->ep.addr, &uvBuf, 1, ret);
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs, int isDelta)
{
    DPS_DBGTRACE();

    if (remote->inbound.interests) {
        if (isDelta) {
            DPS_DBGPRINT("Received interests delta\n");
            DPS_BitVectorXor(interests, interests, remote->inbound.interests, NULL);
        }
        DPS_ClearInboundInterests(node, remote);
    }
    if (DPS_BitVectorIsClear(interests)) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    } else {
        DPS_CountVectorAdd(node->interests, interests);
        DPS_CountVectorAdd(node->needs, needs);
        remote->inbound.interests = interests;
        remote->inbound.needs = needs;
    }

    if (DPS_DEBUG_ENABLED()) {
        DPS_DBGPRINT("New inbound interests from %s: ", DESCRIBE(remote));
        DPS_DumpMatchingTopics(remote->inbound.interests);
    }

    return DPS_OK;
}

DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf)
{
    static const int32_t NeedKeys[] = { DPS_CBOR_KEY_SEQ_NUM };
    static const int32_t WantKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_SUB_FLAGS, DPS_CBOR_KEY_MESH_ID, DPS_CBOR_KEY_NEEDS, DPS_CBOR_KEY_INTERESTS, DPS_CBOR_KEY_PATH };
    static const int32_t WantKeysMask = (1 << DPS_CBOR_KEY_SUB_FLAGS) | (1 << DPS_CBOR_KEY_MESH_ID) | (1 << DPS_CBOR_KEY_NEEDS) | (1 << DPS_CBOR_KEY_INTERESTS);
    DPS_RxBuffer* rxBuf = (DPS_RxBuffer*)buf;
    DPS_Status ret;
    DPS_BitVector* interests = NULL;
    DPS_BitVector* needs = NULL;
    uint16_t port;
    uint32_t revision = 0;
    RemoteNode* remote = NULL;
    CBOR_MapState mapState;
    uint8_t* bytes = NULL;
    DPS_UUID meshId;
    uint8_t flags = 0;
    uint16_t keysMask;
    int remoteIsNew = DPS_FALSE;
    char* path = NULL;
    size_t pathLen = 0;

    DPS_DBGTRACE();

    CBOR_Dump("Sub in", rxBuf->rxPos, DPS_RxBufferAvail(rxBuf));
    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, rxBuf, NeedKeys, A_SIZEOF(NeedKeys), WantKeys, A_SIZEOF(WantKeys));
    if (ret != DPS_OK) {
        return ret;
    }
    keysMask = 0;
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key = 0;
        size_t len;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PORT:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUint16(rxBuf, &port);
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(rxBuf, &revision);
            break;
        case DPS_CBOR_KEY_SUB_FLAGS:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUint8(rxBuf, &flags);
            break;
        case DPS_CBOR_KEY_MESH_ID:
            keysMask |= (1 << key);
            ret = CBOR_DecodeBytes(rxBuf, (uint8_t**)&bytes, &len);
            if ((ret == DPS_OK) && (len != sizeof(DPS_UUID))) {
                ret = DPS_ERR_INVALID;
            } else if (memcpy_s(meshId.val, sizeof(meshId.val), bytes, len) != EOK) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_INTERESTS:
            keysMask |= (1 << key);
            if (interests) {
                ret = DPS_ERR_INVALID;
            } else {
                interests = DPS_BitVectorAlloc();
                if (interests) {
                    ret = DPS_BitVectorDeserialize(interests, rxBuf);
                } else {
                    ret = DPS_ERR_RESOURCES;
                }
            }
            break;
        case DPS_CBOR_KEY_NEEDS:
            keysMask |= (1 << key);
            if (needs) {
                ret = DPS_ERR_INVALID;
            } else {
                needs = DPS_BitVectorAllocFH();
                if (needs) {
                    ret = DPS_BitVectorDeserializeFH(needs, rxBuf);
                } else {
                    ret = DPS_ERR_RESOURCES;
                }
            }
            break;
        case DPS_CBOR_KEY_PATH:
            keysMask |= (1 << key);
            ret = CBOR_DecodeString(rxBuf, &path, &pathLen);
            if ((ret == DPS_OK) && (pathLen >= DPS_NODE_ADDRESS_PATH_MAX)) {
                ret = DPS_ERR_INVALID;
            }
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    if ((keysMask & ((1 << DPS_CBOR_KEY_PORT) | (1 << DPS_CBOR_KEY_PATH))) == 0) {
        DPS_WARNPRINT("Missing required key\n");
        ret = DPS_ERR_INVALID;
    }
    if (ret != DPS_OK) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
        return ret;
    }
    /*
     * Record which port the sender is listening on
     */
    if (keysMask & (1 << DPS_CBOR_KEY_PORT)) {
        DPS_EndpointSetPort(ep, port);
    } else {
        assert(keysMask & (1 << DPS_CBOR_KEY_PATH));
        DPS_EndpointSetPath(ep, path, pathLen);
    }
    keysMask &= ~((1 << DPS_CBOR_KEY_PORT) | (1 << DPS_CBOR_KEY_PATH));
#if SIMULATE_PACKET_LOSS
    /*
     * Enable this code to simulate lost subscriptions to test
     * out the resynchronization code.
     */
    if (((DPS_Rand() % SIMULATE_PACKET_LOSS) == 1)) {
        DPS_PRINT("%s Simulating lost subscription from %s\n", node->addrStr,
                  DPS_NodeAddrToString(&ep->addr));
        return DPS_OK;
    }
#endif
    /*
     * If the regular subscription keys are empty this mean the remote has asked to unlink
     */
    if (keysMask == 0) {
        DPS_DBGPRINT("Received unlink\n");
        DPS_LockNode(node);
        remote = DPS_LookupRemoteNode(node, &ep->addr);
        if (remote) {
            SendSubscriptionAck(node, remote, revision, DPS_FALSE);
            DPS_DeleteRemoteNode(node, remote);
            /*
             * Evaluate impact of losing the remote's interests
             */
            DPS_UpdateSubs(node);
        }
        DPS_UnlockNode(node);
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
        return DPS_OK;
    }

    DPS_LockNode(node);
    if ((keysMask & WantKeysMask) != WantKeysMask) {
        DPS_WARNPRINT("Missing required subscription key\n");
        ret = DPS_ERR_INVALID;
        goto DiscardAndExit;
    }
    if (ret == DPS_OK) {
        ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, &remote);
        if (ret == DPS_ERR_EXISTS) {
            ret = DPS_OK;
        } else {
            ret = DPS_ClearOutboundInterests(remote);
            remoteIsNew = DPS_TRUE;
        }
    }
    if (ret != DPS_OK) {
        goto DiscardAndExit;
    }
    /*
     * Discard stale subscriptions
     */
    if (revision < remote->inbound.revision) {
        DPS_DBGPRINT("%s Stale subscription %d from %s (expected %d)\n", node->addrStr, revision,
                     DESCRIBE(remote), remote->inbound.revision + 1);
        goto DiscardAndExit;
    }
    /*
     * Duplicate - presumably an ACK got lost
     */
    if (revision == remote->inbound.revision) {
        ret = SendSubscriptionAck(node, remote, revision, remote->outbound.includeSub);
        goto DiscardAndExit;
    }
    remote->inbound.revision = revision;

    DPS_DBGPRINT("Node %s received mesh id %08x from %s\n", node->addrStr, UUID_32(&meshId),
                 DESCRIBE(remote));
    /*
     * Loops can be detected by either end of a link and corrective action is required
     * to prevent interests from propagating around the loop. The corrective action is
     * to mute the link by clearing all inbound and outbound interests from the remote.
     */
    if (flags & DPS_SUB_FLAG_MUTE_IND) {
        remote->inbound.muted = DPS_TRUE;
        if (!remote->outbound.muted) {
            DPS_MuteRemoteNode(node, remote);
            ret = DPS_LinkMonitorStart(node, remote);
        }
    } else if (remote->inbound.muted) {
        DPS_DBGPRINT("Remote %s has unumuted\n", DESCRIBE(remote));
        ret = DPS_UnmuteRemoteNode(node, remote);
    } else if (DPS_MeshHasLoop(node, remote, &meshId)) {
        DPS_DBGPRINT("Loop detected by %s for %s\n", node->addrStr, DESCRIBE(remote));
        if (!remote->outbound.muted) {
            DPS_MuteRemoteNode(node, remote);
        }
    }

    if (!remote->outbound.muted) {
        int isDelta = (flags & DPS_SUB_FLAG_DELTA_IND) != 0;
        memcpy_s(&remote->inbound.meshId, sizeof(remote->inbound.meshId), &meshId, sizeof(DPS_UUID));
        ret = UpdateInboundInterests(node, remote, interests, needs, isDelta);
        /*
         * Evaluate impact of the change in interests
         */
        if (ret == DPS_OK) {
            DPS_UpdatePubs(node);
        }
    } else {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    }
    /*
     * Track the minimum mesh id we have seen
     */
    if (DPS_UUIDCompare(&meshId, &node->minMeshId) < 0) {
        memcpy_s(&node->minMeshId, sizeof(node->minMeshId), &meshId, sizeof(DPS_UUID));
    }
    /*
     * All is good so send an ACK
     */
    if (ret == DPS_OK) {
        if (remoteIsNew) {
            DPS_UpdateOutboundInterests(node, remote, &remote->outbound.includeSub);
        }
        ret = SendSubscriptionAck(node, remote, revision, remote->outbound.includeSub);
    }
    DPS_UnlockNode(node);
    DPS_UpdateSubs(node);
    return ret;

DiscardAndExit:

    DPS_UnlockNode(node);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Subscription was discarded %s\n", DPS_ErrTxt(ret));
    }
    DPS_BitVectorFree(interests);
    DPS_BitVectorFree(needs);
    return ret;
}

DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf)
{
    static const int32_t UnprotectedKeys[] = { DPS_CBOR_KEY_ACK_SEQ_NUM };
    static const int32_t UnprotectedOptKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_PATH };
    DPS_RxBuffer* rxBuf = (DPS_RxBuffer*)buf;
    uint8_t* rxPos;
    DPS_Status ret;
    uint16_t port;
    uint32_t revision = 0;
    RemoteNode* remote = NULL;
    CBOR_MapState mapState;
    char* path = NULL;
    size_t pathLen;
    uint16_t keysMask;

    DPS_DBGTRACE();

    /*
     * Decode subscription fields if they are present
     */
    rxPos = rxBuf->rxPos;
    ret = DPS_DecodeSubscription(node, ep, buf);
    rxBuf->rxPos = rxPos;

    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, rxBuf, UnprotectedKeys, A_SIZEOF(UnprotectedKeys),
                           UnprotectedOptKeys, A_SIZEOF(UnprotectedOptKeys));
    if (ret != DPS_OK) {
        return ret;
    }
    keysMask = 0;
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PORT:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUint16(rxBuf, &port);
            break;
        case DPS_CBOR_KEY_ACK_SEQ_NUM:
            ret = CBOR_DecodeUint32(rxBuf, &revision);
            break;
        case DPS_CBOR_KEY_PATH:
            keysMask |= (1 << key);
            ret = CBOR_DecodeString(rxBuf, &path, &pathLen);
            if ((ret == DPS_OK) && (pathLen >= DPS_NODE_ADDRESS_PATH_MAX)) {
                ret = DPS_ERR_INVALID;
            }
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        return ret;
    }
    if ((keysMask & ((1 << DPS_CBOR_KEY_PORT) | (1 << DPS_CBOR_KEY_PATH))) == 0) {
        DPS_WARNPRINT("Missing required key\n");
        return DPS_ERR_INVALID;
    }
    /*
     * Record which port the sender is listening on
     */
    if (keysMask & (1 << DPS_CBOR_KEY_PORT)) {
        DPS_EndpointSetPort(ep, port);
    } else {
        assert(keysMask & (1 << DPS_CBOR_KEY_PATH));
        DPS_EndpointSetPath(ep, path, pathLen);
    }
#if SIMULATE_PACKET_LOSS
    /*
     * Enable this code to simulate lost subscriptions to test
     * out the resynchronization code.
     */
    if (((DPS_Rand() % SIMULATE_PACKET_LOSS) == 1)) {
        DPS_PRINT("%s Simulating lost sub ack from %s\n", node->addrStr,
                  DPS_NodeAddrToString(&ep->addr));
        return DPS_OK;
    }
#endif
    DPS_LockNode(node);
    remote = DPS_LookupRemoteNode(node, &ep->addr);
    if (remote && remote->outbound.revision == revision) {
        remote->outbound.includeSub = DPS_FALSE;
        remote->outbound.ackCountdown = 0;
        if (remote->completion) {
            DPS_RemoteCompletion(node, remote, DPS_OK);
        }
        if (remote->outbound.muted && !remote->monitor) {
            remote->inbound.muted = DPS_TRUE;
            ret = DPS_LinkMonitorStart(node, remote);
        }
    }
    DPS_UnlockNode(node);
    return ret;
}

DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler)
{
    size_t i;
    DPS_Status ret = DPS_OK;
    DPS_Node* node = sub ? sub->node : NULL;

    DPS_DBGTRACE();

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
    if (DPS_DEBUG_ENABLED()) {
        DPS_DumpTopics((const char**)sub->topics, sub->numTopics);
    }

    DPS_BitVectorFuzzyHash(sub->needs, sub->bf);
    /*
     * Protect the node while we update it
     */
    DPS_LockNode(node);
    /*
     * We don't need a mesh id for this node until we have local subscriptions
     */
    if (!node->subscriptions) {
        DPS_GenerateUUID(&node->meshId);
        DPS_DBGPRINT("Node mesh id for %s: %08x\n", node->addrStr, UUID_32(&node->meshId));
    }
    sub->next = node->subscriptions;
    node->subscriptions = sub;
    ret = DPS_CountVectorAdd(node->interests, sub->bf);
    if (ret == DPS_OK) {
        ret = DPS_CountVectorAdd(node->needs, sub->needs);
    }
    DPS_UnlockNode(node);
    if (ret == DPS_OK) {
        DPS_UpdateSubs(node);
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
    DPS_DBGPRINT("Current subscriptions:\n");
    if (DPS_DEBUG_ENABLED()) {
        DPS_Subscription* sub;
        for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
            DPS_DumpTopics((const char**)sub->topics, sub->numTopics);
        }
    }
}
