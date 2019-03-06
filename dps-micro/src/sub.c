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


#define DPS_SUB_FLAG_DELTA_IND  0x01      /* Indicate interests is a delta */
#define DPS_SUB_FLAG_MUTE_IND   0x02      /* Mute has been indicated */


static DPS_Status SendSubscriptionAck(DPS_Node* node, DPS_NodeAddress* dest, uint32_t revision, int includeSub);


DPS_Status DPS_InitSubscription(DPS_Node* node, DPS_Subscription* sub, const char* const* topics, size_t numTopics)
{
    DPS_Status ret = DPS_OK;
    size_t i;

    DPS_DBGTRACE();

    if (!node || !sub || !topics) {
        return DPS_ERR_NULL;
    }
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    if (numTopics > DPS_MAX_SUB_TOPICS) {
        return DPS_ERR_RESOURCES;
    }
    memset(sub, 0, sizeof(DPS_Subscription));

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
    //DPS_BitVectorDump(&sub->bf, DPS_TRUE);
    return ret;
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
    //DPS_BitVectorDump(&node->interests, DPS_TRUE);
    //DPS_BitVectorFuzzyHash(&node->needs, &node->interests);
    ++node->revision;
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
    }
    sub->handler = handler;
    sub->userData = data;
    return DPS_OK;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_DBGTRACE();

    if (!sub) {
        return DPS_ERR_NULL;
    }
    if (UnlinkSub(sub)) {
        /* This tell the upstream node that subscriptions have changed */
        DPS_UpdateSubs(sub->node);
    }
    memset(sub, 0, sizeof(DPS_Subscription));
    return DPS_OK;
}

DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf)
{
    static const int32_t NeedKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_SEQ_NUM };
    static const int32_t WantKeys[] = { DPS_CBOR_KEY_SUB_FLAGS, DPS_CBOR_KEY_MESH_ID, DPS_CBOR_KEY_NEEDS, DPS_CBOR_KEY_INTERESTS };
    static const int32_t WantKeysMask = (1 << DPS_CBOR_KEY_SUB_FLAGS) | (1 << DPS_CBOR_KEY_MESH_ID) | (1 << DPS_CBOR_KEY_NEEDS) | (1 << DPS_CBOR_KEY_INTERESTS);
    DPS_Status ret;
    uint16_t port;
    uint32_t revision = 0;
    CBOR_MapState mapState;
    uint8_t* bytes = NULL;
    DPS_UUID meshId;
    uint8_t flags = 0;
    uint16_t keysMask;
    DPS_Subscription* sub;

    DPS_DBGTRACE();

    CBOR_Dump("Sub in", buf->rxPos, DPS_RxBufferAvail(buf));
    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, buf, NeedKeys, A_SIZEOF(NeedKeys), WantKeys, A_SIZEOF(WantKeys));
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
        size_t len;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
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
            ret = CBOR_DecodeBytes(buf, (uint8_t**)&bytes, &len);
            if ((ret == DPS_OK) && (len != sizeof(DPS_UUID))) {
                ret = DPS_ERR_INVALID;
            } else {
                memcpy(meshId.val, bytes, len);
            }
            break;
        case DPS_CBOR_KEY_INTERESTS:
            keysMask |= (1 << key);
            ret = DPS_BitVectorDeserialize(&sub->bf, buf);
            break;
        case DPS_CBOR_KEY_NEEDS:
            keysMask |= (1 << key);
            ret = DPS_FHBitVectorDeserialize(&sub->needs, buf);
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
    DPS_NodeAddressSetPort(from, port);
    /*
     * If the regular subscription keys are empty this mean the remote has asked to unlink
     */
    if (keysMask == 0) {
        if (node->linked && DPS_SameNodeAddress(from, node->remoteNode)) {
            node->linked = DPS_FALSE;
        }
        ret = SendSubscriptionAck(node, from, revision, DPS_FALSE);
        goto DecodeSubExit;
    }
    if ((keysMask & WantKeysMask) != WantKeysMask) {
        ret = DPS_ERR_INVALID;
        goto DecodeSubExit;
    }
    if (node->linked && !DPS_SameNodeAddress(from, node->remoteNode)) {
        /*
         * We are already linked so ACK but reject the link request.
         *
         * TODO - implement an NACK capability
         */
        ret = SendSubscriptionAck(node, from, revision, DPS_FALSE);
        goto DecodeSubExit;
    }
    /*
     * Discard stale subscriptions
     */
    if (revision < node->remoteRevision) {
        DPS_DBGPRINT("Stale subscription %d (expected %d)\n", revision, node->revision + 1);
        goto DecodeSubExit;
    }
    /*
     * Duplicate - presumably an ACK got lost
     */
    if (revision == node->remoteRevision) {
        ret = SendSubscriptionAck(node, from, revision, DPS_TRUE);
        goto DecodeSubExit;
    }
    /*
     * We don't expect a delta from an unlinked node
     */
    if (flags & DPS_SUB_FLAG_DELTA_IND && !node->linked) {
        DPS_ERRPRINT("Subscription delta was not expected\n");
        ret = DPS_ERR_INVALID;
        goto DecodeSubExit;
    }
    ret = SendSubscriptionAck(node, from, revision, DPS_TRUE);
    if (ret == DPS_OK) {
        if (!node->linked) {
            DPS_CopyNodeAddress(node->remoteNode, from);
            node->remoteRevision = revision;
            node->linked = DPS_TRUE;
        }
        if (flags & DPS_SUB_FLAG_DELTA_IND) {
            DPS_BitVectorXor(&node->interests, &node->interests, &sub->bf, NULL);
        } else {
            DPS_BitVectorDup(&node->interests, &sub->bf);
        }
        DPS_FHBitVectorDup(&node->needs, &sub->needs);
    }

DecodeSubExit:
    DPS_Free(sub, DPS_ALLOC_BRIEF);
    return ret;
}

static DPS_Status SendSubscriptionAck(DPS_Node* node, DPS_NodeAddress* dest, uint32_t revision, int includeSub)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    size_t len;
    uint8_t flags = 0;

    DPS_DBGTRACE();
    DPS_DBGPRINT("Revision %d includeSub %s\n", revision, includeSub ? "TRUE" : "FALSE");

    /* Reset the Tx buffer pools */
    DPS_TxBufferFreePool(node, DPS_TX_POOL);
    DPS_TxBufferFreePool(node, DPS_TX_HDR_POOL);
    DPS_TxBufferFreePool(node, DPS_TMP_POOL);

    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t);
    /*
     * The unprotected map
     */
    len += CBOR_SIZEOF_MAP(2) +
        2 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint16_t) +
        CBOR_SIZEOF(uint32_t);

    if (includeSub) {
        len += CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF(uint32_t);
        len += 4 * CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF_BYTES(sizeof(DPS_UUID));
        len += DPS_BitVectorSerializedSize(&node->interests);
        len += DPS_FHBitVectorSerializedSize(&node->needs);
    }
    /*
     * The protected and encrypted maps
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
        ret = CBOR_EncodeMap(&buf, includeSub ? 7 : 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&buf, node->port);
    }
    if (includeSub) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_SEQ_NUM);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint32(&buf, revision);
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
            ret = CBOR_EncodeBytes(&buf, (uint8_t*)&node->meshId, sizeof(DPS_UUID));
        }
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
        ret = CBOR_EncodeUint32(&buf, revision);
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
    return ret;
}

DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf)
{
    static const int32_t UnprotectedKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_ACK_SEQ_NUM };
    DPS_Status ret;
    uint16_t port;
    uint32_t revision = 0;
    CBOR_MapState mapState;
    uint8_t* rxPos = buf->rxPos;

    DPS_DBGTRACE();

    /*
     * Decode subscription fields if they are present
     */
    ret = DPS_DecodeSubscription(node, from, buf);
    buf->rxPos = rxPos;

    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, buf, UnprotectedKeys, A_SIZEOF(UnprotectedKeys), NULL, 0);
    if (ret != DPS_OK) {
        return ret;
    }
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PORT:
            ret = CBOR_DecodeUint16(buf, &port);
            break;
        case DPS_CBOR_KEY_ACK_SEQ_NUM:
            ret = CBOR_DecodeUint32(buf, &revision);
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    return ret;
}
