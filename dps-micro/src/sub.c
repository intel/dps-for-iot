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
#include <stdlib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include <dps/private/node.h>
#include <dps/private/bitvec.h>
#include <dps/private/topics.h>
#include <dps/private/io_buf.h>
#include <dps/private/sub.h>
#include <dps/private/malloc.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#define DPS_SUB_FLAG_DELTA_IND   0x01      /* Indicate interests is a delta */
#define DPS_SUB_FLAG_SAK_REQ     0x02      /* An acknowledgement is requested for the subscription */
#define DPS_SUB_FLAG_UNLINK_IND  0x04      /* Indicates remote is unlinking */
#define DPS_SUB_FLAG_MUTE_IND    0x08      /* Indicates link has been muted */
#define DPS_SUB_FLAG_UNMUTE_REQ  0x10      /* Remote is requesting to unmute */


static DPS_Status SendSubscriptionAck(DPS_Node* node, DPS_NodeAddress* dest, int includeSub, int collision);


DPS_Subscription* DPS_InitSubscription(DPS_Node* node, const char* const* topics, size_t numTopics)
{
    DPS_Status ret = DPS_OK;
    DPS_Subscription* sub;
    size_t i;

    DPS_DBGTRACE();

    if (!node || !topics) {
        return NULL;
    }
    if (numTopics == 0) {
        return NULL;
    }
    if (numTopics > DPS_MAX_SUB_TOPICS) {
        return NULL;
    }
    sub = DPS_Calloc(sizeof(DPS_Subscription), DPS_ALLOC_LONG_TERM);
    if (!sub) {
        return NULL;
    }
    sub->node = node;
    /*
     * Add the topics to the subscription
     */
    for (i = 0; i < numTopics; ++i) {
        ret = DPS_AddTopic(&sub->bf, topics[i], node->separators, DPS_SubTopic);
        if (ret != DPS_OK) {
            break;
        }
        sub->topics[i] = topics[i];
        ++sub->numTopics;
    }
    return sub;
}

/*
 * Unlink a subscription if it is linked
 */
static int UnlinkSub(DPS_Subscription* sub)
{
    if (sub->node->subscriptions == sub) {
        sub->node->subscriptions = sub->next;
        return DPS_TRUE;
    } else {
        DPS_Subscription* prev = sub->node->subscriptions;
        while (prev && (prev->next != sub)) {
            prev = prev->next;
        }
        if (prev) {
            prev->next = sub->next;
            return DPS_TRUE;
        }
    }
    ++sub->node->revision;
    return DPS_FALSE;
}

DPS_Status DPS_UpdateSubs(DPS_Node* node)
{
    DPS_Status ret = DPS_OK;
    DPS_Subscription* sub = node->subscriptions;

    DPS_BitVectorClear(&node->interests);
    for (sub = node->subscriptions; sub; sub = sub->next) {
        size_t i;
        for (i = 0; i < sub->numTopics; ++i) {
            ret = DPS_AddTopic(&node->interests, sub->topics[i], node->separators, DPS_SubTopic);
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    if (ret == DPS_OK && node->state != REMOTE_UNLINKED) {
        ret = DPS_SendSubscription(node, node->remoteNode);
    }
    return ret;
}

DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler, void* data)
{
    if (!sub || !handler) {
        return DPS_ERR_NULL;
    }
    if (!sub->handler) {
        sub->next = sub->node->subscriptions;
        sub->node->subscriptions = sub;
        /* This tells the upstream node that subscriptions have changed */
        DPS_UpdateSubs(sub->node);
        ++sub->node->revision;
    }
    sub->handler = handler;
    sub->userData = data;
    return DPS_OK;
}

void DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_DBGTRACE();

    if (sub) {
        if (UnlinkSub(sub)) {
            /* This tell the upstream node that subscriptions have changed */
            DPS_UpdateSubs(sub->node);
        }
        DPS_Free(sub, DPS_ALLOC_LONG_TERM);
    }
}

static DPS_Status UnlinkRemote(DPS_Node* node, DPS_NodeAddress* from)
{
    DPS_DBGTRACE();
    node->state = REMOTE_UNLINKED;
    return SendSubscriptionAck(node, from, DPS_FALSE, DPS_FALSE);
}

static DPS_Status DecodeSubscription(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf, uint32_t* sakSeqNum)
{
    /* All subscription messages require these keys */
    static const int32_t ReqKeys[] = { DPS_CBOR_KEY_SEQ_NUM, DPS_CBOR_KEY_SUB_FLAGS, DPS_CBOR_KEY_MESH_ID };
    /* These keys are optional depending on message specifics */
    static const int32_t OptKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_NEEDS, DPS_CBOR_KEY_INTERESTS, DPS_CBOR_KEY_ACK_SEQ_NUM, DPS_CBOR_KEY_PATH };
    /* These keys are required for full subscriptions */
    static const int32_t OptKeysMask = (1 << DPS_CBOR_KEY_NEEDS) | (1 << DPS_CBOR_KEY_INTERESTS);
    DPS_Status ret;
    uint16_t port;
    uint32_t revision = 0;
    CBOR_MapState mapState;
    uint8_t flags = 0;
    uint16_t keysMask;
    DPS_Subscription* sub;
    DPS_UUID meshId;
    int collision = DPS_FALSE;
    int isDuplicate = DPS_FALSE;
    int newRemote = DPS_FALSE;

    DPS_DBGTRACE();

    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, buf, ReqKeys, A_SIZEOF(ReqKeys), OptKeys, A_SIZEOF(OptKeys));
    if (ret != DPS_OK) {
        return ret;
    }

    sub = DPS_Malloc(sizeof(DPS_Subscription), DPS_ALLOC_BRIEF);
    if (!sub) {
        return DPS_ERR_RESOURCES;
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
            ret = CBOR_DecodeUint16(buf, &port);
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(buf, &revision);
            break;
        case DPS_CBOR_KEY_SUB_FLAGS:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUint8(buf, &flags);
            break;
        case DPS_CBOR_KEY_MESH_ID:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUUID(buf, &meshId);
            break;
        case DPS_CBOR_KEY_INTERESTS:
            keysMask |= (1 << key);
            ret = DPS_BitVectorDeserialize(&sub->bf, buf);
            break;
        case DPS_CBOR_KEY_ACK_SEQ_NUM:
            if (sakSeqNum) {
                ret = CBOR_DecodeUint32(buf, sakSeqNum);
            } else {
                ret = CBOR_Skip(buf, NULL, NULL);
            }
            break;
        case DPS_CBOR_KEY_NEEDS:
            keysMask |= (1 << key);
            ret = DPS_FHBitVectorDeserialize(&sub->needs, buf);
            break;
        case DPS_CBOR_KEY_PATH:
            /* This implementation only supports IP transports */
            ret = DPS_ERR_INVALID;
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        goto DecodeSubExit;
    }
    /*
     * We identify the remote by the port the node is listening on
     */
    if (port == 0) {
        ret = DPS_ERR_INVALID;
        goto DecodeSubExit;
    }
    DPS_NodeAddressSetPort(from, port);

    if (sakSeqNum) {
        /*
         * Processing a SAK so we expect this to be the remote we are linked to
         */
        if (node->state == REMOTE_UNLINKED || !DPS_SameNodeAddress(from, node->remoteNode)) {
            DPS_WARNPRINT("Got SAK from unknown remote %s\n", DPS_NodeAddrToString(from));
            ret = DPS_ERR_MISSING;
        }
    } else {
        if (flags & DPS_SUB_FLAG_UNLINK_IND) {
            if (node->state == REMOTE_LINKED && DPS_SameNodeAddress(from, node->remoteNode)) {
                /*
                 * No check on the revision just unlink
                 */
                node->remoteRevision = revision;
                ret = UnlinkRemote(node, from);
                goto DecodeSubExit;
            }
            ret = DPS_ERR_INVALID;
        } else {
            DPS_DBGPRINT("SUB inbound interests[%d] from %s\n", revision, DPS_NodeAddrToString(from));
            if (node->state == REMOTE_UNLINKED) {
                if (flags & DPS_SUB_FLAG_DELTA_IND) {
                    /*
                     * First SUB cannot be a delta
                     */
                    ret = DPS_ERR_INVALID;
                } else {
                    DPS_CopyNodeAddress(node->remoteNode, from);
                    DPS_BitVectorClear(&node->remoteInterests);
                    node->sakPending = DPS_FALSE;
                    node->state = REMOTE_LINKED;
                    node->remoteRevision = 0;
                    newRemote = DPS_TRUE;
                }
            } else if (node->state == REMOTE_LINKING && node->sakPending) {
                DPS_DBGPRINT("Collision with %s\n", DPS_NodeAddrToString(from));
                collision = DPS_TRUE;
            }
        }
    }
    if (ret != DPS_OK) {
        goto DecodeSubExit;
    }
    /*
     * Discard stale subscriptions
     */
    if (revision < node->remoteRevision) {
        DPS_DBGPRINT("Stale subscription %d (expected %d)\n", revision, node->remoteRevision + 1);
        ret = DPS_ERR_STALE;
        goto DecodeSubExit;
    }
    /*
     * If the revision didn't change we make still need to process the
     * message and send a SAK if required but we don't update interests.
     */
    isDuplicate = node->remoteRevision == revision;
    node->remoteRevision = revision;

    if (flags & DPS_SUB_FLAG_SAK_REQ) {
        if ((keysMask & OptKeysMask) != OptKeysMask) {
            DPS_WARNPRINT("Missing mandatory subscription key\n");
            ret = DPS_ERR_INVALID;
            goto DecodeSubExit;
        }
        if (!isDuplicate) {
            if (flags & DPS_SUB_FLAG_DELTA_IND) {
                DPS_BitVectorXor(&node->remoteInterests, &node->remoteInterests, &sub->bf, NULL);
            } else {
                DPS_BitVectorDup(&node->remoteInterests, &sub->bf);
            }
            DPS_FHBitVectorDup(&node->remoteNeeds, &sub->needs);
        }
        ret = SendSubscriptionAck(node, from, newRemote, collision);
    } else {
        if (!sakSeqNum) {
            DPS_ERRPRINT("SUB expected to always request a SAK\n");
            ret = DPS_ERR_INVALID;
        }
    }

DecodeSubExit:
    DPS_Free(sub, DPS_ALLOC_BRIEF);
    return ret;
}

DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf)
{
    return DecodeSubscription(node, from, buf, NULL);
}

DPS_Status DPS_SendSubscription(DPS_Node* node, DPS_NodeAddress* dest)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    size_t len;
    uint8_t flags = DPS_SUB_FLAG_SAK_REQ;
    uint8_t numMapEntries = node->state == REMOTE_UNLINKING ? 4 : 6;

    DPS_DBGTRACE();
    DPS_DBGTRACEA("To %s rev# %d\n", DPS_NodeAddrToString(dest), node->revision);

    /* Reset the Tx buffer pools */
    DPS_TxBufferFreePool(node, DPS_TX_POOL);
    DPS_TxBufferFreePool(node, DPS_TX_HDR_POOL);
    DPS_TxBufferFreePool(node, DPS_TMP_POOL);

    /*
     * Set flags
     */
    if (node->state == REMOTE_UNLINKING) {
        flags |= DPS_SUB_FLAG_UNLINK_IND;
    }
    len = CBOR_SIZEOF_ARRAY(5) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(numMapEntries) + numMapEntries * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +                /* flags */
        CBOR_SIZEOF(uint32_t) +               /* seq_num */
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) + /* mesh id */
        CBOR_SIZEOF(uint16_t);                /* port */
   
    if (node->state != REMOTE_UNLINKING) {
        /*
         * Not currently supporting delta interests in this implementation
         */
        len += DPS_BitVectorSerializedSize(&node->interests);
        len += DPS_FHBitVectorSerializedSize(&node->needs);
    }
    /*
     * The protected and encrypted maps are both empty for SUBs
     */
    len += CBOR_SIZEOF_MAP(0) + CBOR_SIZEOF_MAP(0);

    ret = DPS_TxBufferReserve(node, &buf, len, DPS_TX_POOL);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&buf, 5);
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
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&buf, node->port);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&buf, node->revision);
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
        ret = CBOR_EncodeUUID(&buf, &node->meshId);
    }
    if (node->state != REMOTE_UNLINKING) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_NEEDS);
        }
        if (ret == DPS_OK) {
            ret = DPS_FHBitVectorSerialize(&node->needs, &buf);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_INTERESTS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(&node->interests, &buf);
        }
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
        DPS_TxBufferCommit(&buf);
        ret = DPS_UnicastSend(node, dest, NULL, NULL);
    }
    if (ret == DPS_OK) {
        node->sakPending = DPS_TRUE;
    }
    return ret;
}

DPS_Status SendSubscriptionAck(DPS_Node* node, DPS_NodeAddress* dest, int sendInterests, int collision)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    size_t len;
    uint8_t flags = 0;
    uint8_t numMapEntries = 5;

    DPS_DBGTRACE();
    DPS_DBGPRINT("Revision %d%s\n", node->remoteRevision, sendInterests ? " with interests" : "");

    /* Reset the Tx buffer pools */
    DPS_TxBufferFreePool(node, DPS_TX_POOL);
    DPS_TxBufferFreePool(node, DPS_TX_HDR_POOL);
    DPS_TxBufferFreePool(node, DPS_TMP_POOL);

    /*
     * Set flags
     */
    if (node->state == REMOTE_UNLINKING) {
        flags |= DPS_SUB_FLAG_UNLINK_IND;
    }
    /*
     * Whenever interests are sent a SAK is required
     */
    if (!collision && sendInterests) {
        numMapEntries += 2;
        flags |= DPS_SUB_FLAG_SAK_REQ;
    }
    len = CBOR_SIZEOF_ARRAY(5) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(numMapEntries) + numMapEntries * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +                /* flags */
        CBOR_SIZEOF(uint32_t) +               /* seq_num */
        CBOR_SIZEOF(uint32_t) +               /* ack_seq_num */
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) + /* mesh id */
        CBOR_SIZEOF(uint16_t);                /* port */
   
    if (flags & DPS_SUB_FLAG_SAK_REQ) {
        len += DPS_BitVectorSerializedSize(&node->interests);
        len += DPS_FHBitVectorSerializedSize(&node->needs);
    }
    /*
     * The protected and encrypted maps are both empty for SAKs
     */
    len += CBOR_SIZEOF_MAP(0) + CBOR_SIZEOF_MAP(0);

    ret = DPS_TxBufferReserve(node, &buf, len, DPS_TX_POOL);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&buf, 5);
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
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&buf, node->port);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&buf, node->revision);
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
        ret = CBOR_EncodeUUID(&buf, &node->meshId);
    }
    if (flags & DPS_SUB_FLAG_SAK_REQ) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_NEEDS);
        }
        if (ret == DPS_OK) {
            ret = DPS_FHBitVectorSerialize(&node->needs, &buf);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_INTERESTS);
        }
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(&node->interests, &buf);
        }
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_ACK_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&buf, node->remoteRevision);
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
        DPS_TxBufferCommit(&buf);
        ret = DPS_UnicastSend(node, dest, NULL, NULL);
    }
    if (ret == DPS_OK) {
        if (flags & DPS_SUB_FLAG_SAK_REQ) {
            node->sakPending = DPS_TRUE;
        }
    }
    return ret;
}

DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf)
{
    DPS_Status ret;
    uint32_t revision = 0;

    DPS_DBGTRACE();

    /*
     * Decode subscription fields if they are present
     */
    ret = DecodeSubscription(node, from, buf, &revision);
    if (ret == DPS_OK) {
        if (node->revision == revision) {
            node->sakPending = DPS_FALSE;
        } else {
            DPS_WARNPRINT("Unexpected revision in SAK from %s, expected %d got %d\n", DPS_NodeAddrToString(from), node->revision, revision);
            ret = DPS_ERR_STALE;
        }
    }
    return ret;
}
