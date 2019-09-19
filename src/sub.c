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
#include "node.h"
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "topics.h"

#undef DPS_DBG_TAG
#define DPS_DBG_TAG ((node)->addrStr)

/*
 * Debug control for this module
 */
#if defined(DEBUG_LOOP_DETECTION)
DPS_DEBUG_CONTROL(DPS_DEBUG_INFO);
#else
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);
#endif

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

#define DPS_SUB_FLAG_DELTA_IND   0x01      /* Indicate interests is a delta */
#define DPS_SUB_FLAG_MUTE_IND    0x02      /* Mute has been indicated */
#define DPS_SUB_FLAG_UNLINK_REQ  0x04      /* Subscription message is requesting to unlink */
#define DPS_SUB_FLAG_SAK_REQ     0x08      /* An acknowledgement is requested for the subscription */
#define DPS_SUB_FLAG_UNMUTE_REQ  0x10      /* Remote is requesting to unmute a link */

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

DPS_Status DPS_SubscribeExpired(DPS_Subscription* sub, int enable)
{
    if (!sub) {
        return DPS_ERR_ARGS;
    }
    if (enable) {
        sub->flags |= SUB_FLAG_EXPIRED;
    } else {
        sub->flags &= ~SUB_FLAG_EXPIRED;
    }
    return DPS_OK;
}

DPS_Subscription* DPS_FreeSubscription(DPS_Subscription* sub)
{
    DPS_Subscription* next = sub->next;
    assert((sub->flags & SUB_FLAG_WAS_FREED) && (sub->refCount == 0));
    if (sub->onDestroyed) {
        sub->onDestroyed(sub);
    }
    DPS_BitVectorFree(sub->bf);
    DPS_BitVectorFree(sub->needs);
    while (sub->numTopics) {
        free(sub->topics[--sub->numTopics]);
    }
    free(sub);
    return next;
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
        sub->next = node->freeSubs;
        node->freeSubs = sub;
        sub->flags = SUB_FLAG_WAS_FREED;
    }

    if (sub->refCount == 0) {
        uv_async_send(&node->freeAsync);
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
    sub->flags |= SUB_FLAG_SERIALIZE;
    return sub;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub, DPS_OnSubscriptionDestroyed cb)
{
    DPS_Node* node;

    if (!IsValidSub(sub)) {
        return DPS_ERR_MISSING;
    }
    node = sub->node;

    DPS_DBGTRACE();

    /*
     * Protect the node while we update it
     */
    DPS_LockNode(node);
    DPS_DBGPRINT("Unsubscribing from %zu topics\n", sub->numTopics);
    sub->onDestroyed = cb;
    FreeSubscription(sub);
    DPS_UpdateSubs(node, SubsSendNow);
    DPS_UnlockNode(node);

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
    uint8_t flags = DPS_SUB_FLAG_SAK_REQ;
    uint8_t numMapEntries = remote->state == REMOTE_UNLINKING ? 4 : 6;

    DPS_DBGTRACEA("To %s rev# %d %s\n", DESCRIBE(remote), remote->outbound.revision, RemoteStateTxt(remote));

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
    /*
     * Set flags
     */
    switch (remote->state) {
    case REMOTE_MUTED:
    case REMOTE_DEAD:
        /* We should never be sending subscriptions to muted or dead remotes */
        DPS_ERRPRINT("Attempting to send subscription to %s remote %s\n", RemoteStateTxt(remote), DESCRIBE(remote));
        return DPS_ERR_INVALID;
    case REMOTE_MUTING:
        DPS_DBGINFO("MUTE_IND(%s) to SUB to %s\n", RemoteStateTxt(remote), DESCRIBE(remote));
        flags |= DPS_SUB_FLAG_MUTE_IND;
        break;
    case REMOTE_UNMUTING:
        flags |= DPS_SUB_FLAG_UNMUTE_REQ;
        break;
    case REMOTE_UNLINKING:
        flags |= DPS_SUB_FLAG_UNLINK_REQ;
        break;
    default:
        break;
    }
    if (remote->outbound.deltaInd) {
        flags |= DPS_SUB_FLAG_DELTA_IND;
    }
#ifdef DPS_DEBUG
    ++_DPS_NumSubs;
#endif
    len = CBOR_SIZEOF_ARRAY(5) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(numMapEntries) + numMapEntries * CBOR_SIZEOF(uint8_t) +
           CBOR_SIZEOF(uint8_t) +               /* flags */
           CBOR_SIZEOF(uint32_t) +              /* seq_num */
           CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)); /* mesh id */

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
    if (remote->state != REMOTE_UNLINKING) {
        interests = remote->outbound.deltaInd ? remote->outbound.delta : remote->outbound.interests;
        len += DPS_BitVectorSerializeMaxSize(interests) + DPS_BitVectorSerializeFHSize();
    } else {
        interests = NULL;
    }
    /*
     * The protected and encrypted maps are both empty for SUBS
     */
    len += CBOR_SIZEOF_MAP(0) + CBOR_SIZEOF_MAP(0);

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
        ret = CBOR_EncodeMap(&buf, numMapEntries);
    }
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint16(&buf, DPS_NetAddrPort((const struct sockaddr*)&node->addr.u.inaddr));
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
        ret = CBOR_EncodeUUID(&buf, DPS_MinMeshId(node, remote));
    }
    if (remote->state != REMOTE_UNLINKING) {
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

    if (remote->state != REMOTE_UNLINKING) {
        DPS_DBGPRINT("SUB outbound interests[%d] for %s: %s%s\n", remote->outbound.revision, DESCRIBE(remote),
                     remote->outbound.deltaInd ? "(<delta>)" : "",
                     DPS_DumpMatchingTopics(remote->outbound.interests));
    }

    if (ret == DPS_OK) {
        uv_buf_t uvBuf = uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf));
        CBOR_Dump("SUB out", (uint8_t*)uvBuf.base, uvBuf.len);
        ret = DPS_NetSend(node, NULL, &remote->ep, &uvBuf, 1, DPS_OnSendSubscriptionComplete);
        if (ret == DPS_OK) {
            /*
             * The SAK counter is zeroed the first time this SUB is sent, is
             * incremented while we are waiting for the matching SAK and used
             * to trigger resends in the event of a SAK timeout.
             */
            if (!remote->outbound.sakPending) {
                remote->outbound.sakPending = DPS_TRUE;
                remote->outbound.sakCounter = 0;
            }
            remote->outbound.lastSubMsgType = DPS_MSG_TYPE_SUB;
        } else {
            DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
            remote->outbound.sakPending = DPS_FALSE;
            remote->outbound.lastSubMsgType = 0;
            DPS_SendComplete(node, &remote->ep.addr, &uvBuf, 1, ret);
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

DPS_Status DPS_SendSubscriptionAck(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    DPS_BitVector* interests;
    size_t len;
    uint8_t numMapEntries = 5;
    uint8_t flags = 0;

    DPS_DBGTRACEA("To %s %s rev# %d ack-rev# %d%s\n", DESCRIBE(remote), RemoteStateTxt(remote),
            remote->outbound.revision, remote->inbound.revision, remote->outbound.sendInterests ? " +interests" : "");

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
    /*
     * Set flags
     */
    if (remote->outbound.deltaInd) {
        flags |= DPS_SUB_FLAG_DELTA_IND;
    }
    switch (remote->state) {
    case REMOTE_MUTING:
        flags |= DPS_SUB_FLAG_MUTE_IND;
        /*
         * If we are muting we need the remote to send a SAK
         */
        remote->outbound.sendInterests = DPS_TRUE;
        DPS_DBGINFO("MUTE_IND(MUTING) in SAK to %s\n", DESCRIBE(remote));
        break;
    case REMOTE_MUTED:
        flags |= DPS_SUB_FLAG_MUTE_IND;
        DPS_DBGINFO("MUTE_IND(MUTED) in SAK to %s\n", DESCRIBE(remote));
        break;
    case REMOTE_UNMUTING:
        flags |= DPS_SUB_FLAG_UNMUTE_REQ;
        break;
    case REMOTE_UNLINKING:
        flags |= DPS_SUB_FLAG_UNLINK_REQ;
        break;
    default:
        break;
    }
    /*
     * Whenever interests are sent a SAK is required
     */
    if (remote->outbound.sendInterests) {
        numMapEntries += 2;
        flags |= DPS_SUB_FLAG_SAK_REQ;
    }
    len = CBOR_SIZEOF_ARRAY(5) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(numMapEntries) + numMapEntries * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +               /* flags */
        CBOR_SIZEOF(uint32_t) +              /* seq_num */
        CBOR_SIZEOF(uint32_t) +              /* ack_seq_num */
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)); /* mesh id */

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
    if (remote->outbound.sendInterests) {
        interests = remote->outbound.deltaInd ? remote->outbound.delta : remote->outbound.interests;
        len += DPS_BitVectorSerializeMaxSize(interests) + DPS_BitVectorSerializeFHSize();
    } else {
        interests = NULL;
    }
    /*
     * The protected and encrypted maps are both empty for SAKs
     */
    len += CBOR_SIZEOF_MAP(0) + CBOR_SIZEOF_MAP(0);

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
        ret = CBOR_EncodeMap(&buf, numMapEntries);
    }
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint16(&buf, DPS_NetAddrPort((const struct sockaddr*)&node->addr.u.inaddr));
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
         * only changes if the interests change.
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
        ret = CBOR_EncodeUUID(&buf, DPS_MinMeshId(node, remote));
    }
    if (remote->outbound.sendInterests) {
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
        ret = CBOR_EncodeUint32(&buf, remote->inbound.revision);
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

    if (remote->outbound.sendInterests) {
        DPS_DBGPRINT("SAK outbound interests[%d/%d] for %s: %s%s\n", remote->outbound.revision,
                     remote->inbound.revision, DESCRIBE(remote), remote->outbound.deltaInd ? "(<delta>)" : "",
                     DPS_DumpMatchingTopics(remote->outbound.interests));
    }

    if (ret == DPS_OK) {
        uv_buf_t uvBuf = uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf));
        CBOR_Dump("SAK out", (uint8_t*)uvBuf.base, uvBuf.len);
        ret = DPS_NetSend(node, NULL, &remote->ep, &uvBuf, 1, DPS_OnSendComplete);
        if (ret == DPS_OK) {
            remote->outbound.lastSubMsgType = 0;
            if (flags & DPS_SUB_FLAG_SAK_REQ) {
                /*
                 * The SAK counter is zeroed the first time this SAK is sent, is
                 * incremented while we are waiting for the matching SAK and used
                 * to trigger resends in the event of a SAK timeout.
                 */
                if (!remote->outbound.sakPending) {
                    remote->outbound.sakPending = DPS_TRUE;
                    remote->outbound.sakCounter = 0;
                }
                remote->outbound.lastSubMsgType = DPS_MSG_TYPE_SAK;
            } else {
                remote->outbound.sakPending = DPS_FALSE;
            }
        } else {
            DPS_ERRPRINT("Failed to send SAK %s\n", DPS_ErrTxt(ret));
            remote->outbound.sakPending = DPS_FALSE;
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
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests,
                                         DPS_BitVector* needs, int isDelta)
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
    return DPS_OK;
}

static DPS_Status UnlinkRemote(DPS_Node* node, DPS_NodeAddress* addr)
{
    RemoteNode* remote;

    DPS_DBGPRINT("Received unlink for %s\n", DPS_NodeAddrToString(addr));
    remote = DPS_LookupRemoteNode(node, addr);
    if (remote) {
        remote->outbound.sendInterests = DPS_FALSE;
        DPS_SendSubscriptionAck(node, remote);
        DPS_DeleteRemoteNode(node, remote);
        /*
         * Evaluate impact of losing the remote's interests
         */
        DPS_UpdateSubs(node, SubsSendNow);
        return DPS_OK;
    } else {
        return DPS_ERR_MISSING;
    }
}

/*
 * Each node has a randomly allocated mesh id that is used to detect loops in the mesh.
 *
 * Mesh id's are included in the header of subscription, subscription acknowledgments
 * (SAKS) that include subscription information. SAKs only include subscription information
 * during link establishment, thereafter SAKs contain the minimal information needed for
 * reliable subscription delivery.
 *
 * When a SUB or SAK is sent to a remote node the mesh id is the minimum of the mesh id
 * of the local node and the mesh id's received from all other nodes excluding the remote
 * node itself. The mesh id that was sent is recorded in the outbound.meshId field of the
 * remote node.
 *
 * Loop detection proceeds as follows: when an SUB or SAK is received the mesh id is
 * compared against the mesh id's previously received from all other nodes as recorded in the
 * inbound.meshId fields. If the received mesh id is the same as the mesh id received from
 * any other remote node there must be a loop in the mesh.  This indicates a loop because the
 * only way the same minimal mesh id can be computed by two different remote nodes is if
 * there is another path between those two nodes, i.e., there must be a loop in the mesh.
 */
int MeshHasLoop(DPS_Node* node, RemoteNode* src, DPS_UUID* meshId)
{
    return DPS_UUIDCompare(meshId, DPS_MinMeshId(node, src)) == 0;
}

/*
 * SUBs and SAKs have the same wire format but there are some differences in how
 * how certain field are treated. If we are decoding SAK sakSeqNum is non-NULL.
 */
static DPS_Status DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf, uint32_t* sakSeqNum)
{
    /* All subscription messages require these keys */
    static const int32_t ReqKeys[] = { DPS_CBOR_KEY_SEQ_NUM, DPS_CBOR_KEY_SUB_FLAGS, DPS_CBOR_KEY_MESH_ID };
    /* These keys are optional depending on message specifics */
    static const int32_t OptKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_NEEDS, DPS_CBOR_KEY_INTERESTS, DPS_CBOR_KEY_ACK_SEQ_NUM, DPS_CBOR_KEY_PATH };
    /* These keys are required for full subscriptions */
    static const int32_t OptKeysMask = (1 << DPS_CBOR_KEY_NEEDS) | (1 << DPS_CBOR_KEY_INTERESTS);
    DPS_RxBuffer* rxBuf = (DPS_RxBuffer*)buf;
    DPS_Status ret;
    DPS_BitVector* interests = NULL;
    DPS_BitVector* needs = NULL;
    uint16_t port = 0;
    uint32_t revision = 0;
    RemoteNode* remote = NULL;
    CBOR_MapState mapState;
    DPS_UUID meshId;
    uint8_t flags = 0;
    uint16_t keysMask;
    int remoteIsNew = DPS_FALSE;
    int isDuplicate;
    char* path = NULL;
    size_t pathLen = 0;

    CBOR_Dump("SUB in", rxBuf->rxPos, DPS_RxBufferAvail(rxBuf));
    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, rxBuf, ReqKeys, A_SIZEOF(ReqKeys), OptKeys, A_SIZEOF(OptKeys));
    if (ret != DPS_OK) {
        return ret;
    }
    keysMask = 0;
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key = 0;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            if (ret == DPS_ERR_MISSING) {
                ret = DPS_ERR_INVALID;
            }
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PORT:
            ret = CBOR_DecodeUint16(rxBuf, &port);
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(rxBuf, &revision);
            break;
        case DPS_CBOR_KEY_SUB_FLAGS:
            ret = CBOR_DecodeUint8(rxBuf, &flags);
            break;
        case DPS_CBOR_KEY_MESH_ID:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUUID(rxBuf, &meshId);
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
        case DPS_CBOR_KEY_ACK_SEQ_NUM:
            if (sakSeqNum) {
                ret = CBOR_DecodeUint32(rxBuf, sakSeqNum);
            } else {
                ret = CBOR_Skip(rxBuf, NULL, NULL);
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
    if (ret == DPS_OK) {
        /*
         * Record which port (or path for non-IP protocols) the sender is listening on.
         * all subscription messages must have one (not both) of these two keys.
         */
        if ((port == 0) == (path == NULL)) {
            ret = DPS_ERR_INVALID;
        } else if (port) {
            DPS_EndpointSetPort(ep, port);
        } else {
            DPS_EndpointSetPath(ep, path, pathLen);
        }
    }
    if (ret != DPS_OK) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
        return ret;
    }
#if SIMULATE_PACKET_LOSS
    /*
     * Enable this code to simulate lost SUBs and SAKs to test reliable delivery
     */
    if (((DPS_Rand() % SIMULATE_PACKET_LOSS) == 1)) {
        DPS_PRINT("Simulating lost subscription from %s\n", DPS_NodeAddrToString(&ep->addr));
        return DPS_OK;
    }
#endif
    if (sakSeqNum) {
        DPS_DBGPRINT("SAK inbound interests[%d/%d] from %s: %s%s\n", revision, *sakSeqNum,
                     DPS_NodeAddrToString(&ep->addr), (flags & DPS_SUB_FLAG_DELTA_IND) ? "(<delta>)" : "",
                     (keysMask & (1 << DPS_CBOR_KEY_INTERESTS)) ? DPS_DumpMatchingTopics(interests) : "<null>");
        /*
         * Processing a SAK so we expect the remote to exist
         */
        remote = DPS_LookupRemoteNode(node, &ep->addr);
        if (remote) {
            /*
             * We don't expect a SAK for a DEAD remote
             */
            if (remote->state == REMOTE_DEAD) {
                DPS_ERRPRINT("Received SAK for DEAD remote %s\n", DESCRIBE(remote));
                ret = DPS_ERR_INVALID;
                goto DiscardAndExit;
            }
            /*
             * If the remote is muting the muted flag should have been set in the SAK
             */
            if (remote->state == REMOTE_MUTING && !(flags & DPS_SUB_FLAG_MUTE_IND)) {
                DPS_ERRPRINT("Expected muted flag in SAK from %s\n", DESCRIBE(remote));
                ret = DPS_ERR_INVALID;
            }
        } else {
            DPS_WARNPRINT("Got SAK from unknown remote %s\n", DPS_NodeAddrToString(&ep->addr));
            ret = DPS_ERR_MISSING;
        }
    } else {
        DPS_DBGPRINT("SUB inbound interests[%d] from %s: %s%s\n", revision,
                     DPS_NodeAddrToString(&ep->addr), (flags & DPS_SUB_FLAG_DELTA_IND) ? "(<delta>)" : "",
                     (keysMask & (1 << DPS_CBOR_KEY_INTERESTS)) ? DPS_DumpMatchingTopics(interests) : "<null>");
        if (flags & DPS_SUB_FLAG_UNLINK_REQ) {
            ret = UnlinkRemote(node, &ep->addr);
            goto DiscardAndExit;
        }
        ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, &remote);
        if (ret == DPS_ERR_EXISTS) {
            /*
             * If both sides simultaneously send a SUB they will exchange
             * interests in the SUB messages and must not send interests
             * in their corresponding SAKs.
             */
            if (remote->outbound.sakPending) {
                DPS_DBGPRINT("Collision with %s\n", DESCRIBE(remote));
                remote->outbound.sendInterests = DPS_FALSE;
            }
            ret = DPS_OK;
        } else {
            remoteIsNew = DPS_TRUE;
            ret = DPS_ClearOutboundInterests(remote);
        }
    }
    if (ret != DPS_OK) {
        goto DiscardAndExit;
    }
    /*
     * Discard stale subscription messages
     */
    if (revision < remote->inbound.revision) {
        DPS_DBGPRINT("Stale subscription %d from %s (expected %d)\n", revision, DESCRIBE(remote),
                     remote->inbound.revision + 1);
        goto DiscardAndExit;
    }
    /*
     * If the revision didn't change we make still need to process the
     * message and send a SAK if required but we don't update interests.
     */
    isDuplicate = remote->inbound.revision == revision;
    remote->inbound.revision = revision;

    DPS_DBGINFO("Received mesh id %08x in %s from %s #%d\n", meshId.val32[0], sakSeqNum ? "SAK" : "SUB", DESCRIBE(remote), revision);

    /*
     * Loops can be detected by either end of a link and corrective action is required
     * to prevent interests from propagating around the loop. The corrective action is
     * to mute the link which prevents publications from being forwarded to that remote.
     */
    if (flags & DPS_SUB_FLAG_MUTE_IND) {
        if (sakSeqNum) {
            DPS_DBGINFO("MUTE_IND %s in SAK by %s\n", remote->state == REMOTE_MUTING ? "ackowledged" : "reported", DESCRIBE(remote));
        } else {
            DPS_DBGINFO("MUTE_IND %s in SUB by %s\n", remote->state == REMOTE_MUTING ? "ackowledged" : "reported", DESCRIBE(remote));
        }
        ret = DPS_MuteRemoteNode(node, remote, REMOTE_MUTED);
    } else if (flags & DPS_SUB_FLAG_UNMUTE_REQ) {
        /*
         * Only a SUB can unmute a link
         */
        if (!sakSeqNum) {
            DPS_DBGINFO("UNMUTE_REQ from %s\n", DESCRIBE(remote));
            ret = DPS_UnmuteRemoteNode(node, remote);
        }
    } else if (MeshHasLoop(node, remote, &meshId)) {
        DPS_DBGINFO("Loop detected for %s\n", DESCRIBE(remote));
        ret = DPS_MuteRemoteNode(node, remote, REMOTE_MUTING);
    }
    if (ret != DPS_OK) {
        goto DiscardAndExit;
    }
    if (flags & DPS_SUB_FLAG_SAK_REQ) {
        if ((keysMask & OptKeysMask) != OptKeysMask) {
            DPS_WARNPRINT("Missing mandatory subscription key\n");
            ret = DPS_ERR_INVALID;
            goto DiscardAndExit;
        }
        /*
         * Check remote is in a state where we need to update interests
         */
        if (!isDuplicate && remote->state != REMOTE_MUTED) {
            int isDelta = (flags & DPS_SUB_FLAG_DELTA_IND) != 0;
            ret = UpdateInboundInterests(node, remote, interests, needs, isDelta);
            if (ret != DPS_OK) {
                goto DiscardAndExit;
            }
            /*
             * Evaluate impact of the change in interests
             */
            DPS_UpdatePubs(node);
        } else {
            DPS_BitVectorFree(interests);
            DPS_BitVectorFree(needs);
        }
        if (remoteIsNew) {
            assert(!isDuplicate);
            /*
             * Always send the interests in the first SAK
             */
            ret = DPS_UpdateOutboundInterests(node, remote, &remote->outbound.sendInterests);
            if (ret != DPS_OK) {
                goto DiscardAndExit;
            }
        }
        ret = DPS_SendSubscriptionAck(node, remote);
    } else {
        if (!sakSeqNum) {
            DPS_ERRPRINT("SUB expected to always request a SAK\n");
            ret = DPS_ERR_INVALID;
            goto DiscardAndExit;
        }
        /*
         * This indicates the end of the SUB/SAK transation
         */
        remote->outbound.lastSubMsgType = 0;
        /*
         * These should be NULL but call free just in case
         */
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    }
    remote->inbound.meshId = meshId;
    return ret;

DiscardAndExit:

    if (remoteIsNew) {
        DPS_DeleteRemoteNode(node, remote);
    }
    if (ret != DPS_OK) {
        DPS_DBGPRINT("%s was discarded - %s\n", sakSeqNum ? "SAK" : "SUB", DPS_ErrTxt(ret));
    }
    DPS_BitVectorFree(interests);
    DPS_BitVectorFree(needs);
    return ret;
}

DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf)
{
    DPS_Status ret;
    DPS_DBGTRACEA("From %s\n", DPS_NodeAddrToString(&ep->addr));

    DPS_LockNode(node);
    ret = DecodeSubscription(node, ep, buf, NULL);
    if (ret == DPS_OK) {
        DPS_UpdateSubs(node, SubsThrottled);
    }
    DPS_UnlockNode(node);

    return ret;
}

DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf)
{
    DPS_Status ret;
    uint32_t revision = 0;
    RemoteNode* remote;

    DPS_DBGTRACEA("From %s\n", DPS_NodeAddrToString(&ep->addr));

#if SIMULATE_PACKET_LOSS
    /*
     * Enable this code to simulate lost subscriptions to test
     * out the resynchronization code.
     */
    if (((DPS_Rand() % SIMULATE_PACKET_LOSS) == 1)) {
        DPS_PRINT("Simulating lost sub ack from %s\n", DPS_NodeAddrToString(&ep->addr));
        return DPS_OK;
    }
#endif

    DPS_LockNode(node);
    ret = DecodeSubscription(node, ep, buf, &revision);
    if (ret != DPS_OK) {
        goto Exit;
    }
    remote = DPS_LookupRemoteNode(node, &ep->addr);
    if (remote) {
        if (remote->outbound.revision == revision) {
            remote->outbound.sendInterests = DPS_FALSE;
            remote->outbound.sakPending = DPS_FALSE;
            switch (remote->state) {
            case REMOTE_MUTING:
                /*
                 * If lastSubMsgType == 0 this SUB/SAK transaction is complete but the
                 * state is REMOTE_MUTING so start a new SUB/SAK transaction to inform
                 * the remote that the link is being muted; this happens below.
                 */
                if (remote->outbound.lastSubMsgType != 0) {
                    DPS_DBGINFO("Successfully muted %s\n", DESCRIBE(remote));
                    remote->state = REMOTE_MUTED;
                }
                /* fall through */
            case REMOTE_LINKING:
            case REMOTE_MUTED:
            case REMOTE_UNLINKING:
                if (remote->completion) {
                    DPS_RemoteCompletion(remote->completion, DPS_OK);
                }
                break;
            case REMOTE_UNMUTING:
                DPS_DBGPRINT("Successfully unmuted %s\n", DESCRIBE(remote));
                remote->state = REMOTE_ACTIVE;
                remote->outbound.sakPending = DPS_FALSE;
                break;
            case REMOTE_ACTIVE:
            case REMOTE_DEAD:
                break;
            }
        } else {
            DPS_DBGPRINT("Unexpected revision in SAK from %s, expected %d got %d\n", DESCRIBE(remote),
                         remote->outbound.revision, revision);
            ret = DPS_ERR_INVALID;
        }
    } else {
        ret = DPS_ERR_MISSING;
    }

Exit:
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
    sub->next = node->subscriptions;
    node->subscriptions = sub;
    ret = DPS_CountVectorAdd(node->interests, sub->bf);
    if (ret == DPS_OK) {
        ret = DPS_CountVectorAdd(node->needs, sub->needs);
    }
    if (ret == DPS_OK) {
        DPS_UpdateSubs(node, SubsSendNow);
    }
    DPS_UnlockNode(node);
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

DPS_Status DPS_SubscriptionSetSerialize(DPS_Subscription* sub, int serialize)
{
    if (!sub || !sub->node) {
        return DPS_ERR_NULL;
    }
    DPS_LockNode(sub->node);
    if (serialize) {
        sub->flags |= SUB_FLAG_SERIALIZE;
    } else {
        sub->flags &= ~SUB_FLAG_SERIALIZE;
    }
    DPS_UnlockNode(sub->node);
    return DPS_OK;
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
