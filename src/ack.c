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
#include "bitvec.h"
#include "coap.h"
#include "cbor.h"
#include "ack.h"
#include "pub.h"
#include "history.h"
#include "node.h"
#include "topics.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_Status DPS_SendAcknowledgment(DPS_Node*node, PublicationAck* ack, RemoteNode* ackNode)
{
    DPS_Status ret;
    uv_buf_t bufs[] = {
        { (char*)ack->payload.base, DPS_BufferUsed(&ack->payload) }
    };

    ret = DPS_NetSend(node, &ackNode->ep, bufs, A_SIZEOF(bufs), DPS_OnSendComplete);
    if (ret != DPS_OK) {
        DPS_SendFailed(node, &ack->destAddr, bufs, A_SIZEOF(bufs), ret);
    }
    return ret;
}

static PublicationAck* AllocPubAck(const DPS_UUID* pubId, uint32_t sequenceNum)
{
    PublicationAck* ack = calloc(1, sizeof(PublicationAck));
    if (!ack) {
        return NULL;
    }
    ack->pubId = *pubId;
    ack->sequenceNum = sequenceNum;
    return ack;
}

static DPS_Status ComposeAck(DPS_Node* node, PublicationAck* ack, uint8_t* data, size_t len, DPS_NodeAddress* destAddr)
{
    DPS_Status ret;
    size_t allocSize = 8 + sizeof(DPS_UUID) + sizeof(uint32_t) + len;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    ret = DPS_BufferInit(&ack->payload, NULL, allocSize);
    if (ret != DPS_OK) {
        free(ack);
        return ret;
    }
    CBOR_EncodeUint8(&ack->payload, DPS_MSG_TYPE_ACK);
    CBOR_EncodeBytes(&ack->payload, (uint8_t*)&ack->pubId, sizeof(DPS_UUID));
    CBOR_EncodeUint32(&ack->payload, ack->sequenceNum);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&ack->payload, data, len);
        if (ret != DPS_OK) {
            free(ack->payload.base);
            free(ack);
        } else {
            ack->destAddr = *destAddr;
        }
    }
    return ret;
}

DPS_Status DPS_DecodeAcknowledgment(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_Publication* pub;
    uint32_t sn;
    uint32_t sequenceNum;
    DPS_UUID* pubId;
    DPS_NodeAddress* addr;
    uint8_t* payload;
    size_t len;

    DPS_DBGTRACE();

    ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (len != sizeof(DPS_UUID)) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeUint32(buffer, &sequenceNum);
    if (ret != DPS_OK) {
        return ret;
    }
    if (sequenceNum == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &payload, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_LockNode(node);
    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->handler && (pub->sequenceNum == sequenceNum) && (DPS_UUIDCompare(&pub->pubId, pubId) == 0)) {
            break;
        }
    }
    if (pub) {
        if (pub->handler) {
            DPS_UnlockNode(node);
            pub->handler(pub, payload, len);
            DPS_LockNode(node);
        }
        DPS_UnlockNode(node);
        return DPS_OK;
    }
    DPS_UnlockNode(node);
    /*
     * Look for in the history record for somewhere to forward the ACK
     */
    ret = DPS_LookupPublisher(&node->history, pubId, &sn, &addr);
    if ((ret == DPS_OK) && (sequenceNum <= sn) && addr) {
        PublicationAck* ack = AllocPubAck(pubId, sequenceNum);
        if (ack) {
            DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), sequenceNum, DPS_NodeAddrToString(addr));
            ret = ComposeAck(node, ack, payload, len, addr);
            if (ret == DPS_OK) {
                DPS_QueuePublicationAck(node, ack);
            }
        } else {
            ret = DPS_ERR_RESOURCES;
        }
    }
    return ret;
}

DPS_Status DPS_AckPublication(const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Status ret;
    DPS_NodeAddress* addr = NULL;
    DPS_Node* node = pub ? pub->node : NULL;
    uint32_t sequenceNum;
    PublicationAck* ack;

    DPS_DBGTRACE();

    if (!node) {
        return DPS_ERR_NULL;
    }
    if (pub->flags & PUB_FLAG_LOCAL) {
        return DPS_ERR_INVALID;
    }
    ret = DPS_LookupPublisher(&node->history, &pub->pubId, &sequenceNum, &addr);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!addr) {
        return DPS_ERR_NO_ROUTE;
    }
    DPS_DBGPRINT("Queueing acknowledgement for %s/%d to %s\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum, DPS_NodeAddrToString(addr));
    ack = AllocPubAck(&pub->pubId, pub->sequenceNum);
    if (!ack) {
        return DPS_ERR_RESOURCES;
    }
    ret = ComposeAck(node, ack, payload, len, addr);
    if (ret == DPS_OK) {
        DPS_QueuePublicationAck(node, ack);
    }
    return ret;
}

