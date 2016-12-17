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

void DPS_DestroyAck(PublicationAck* ack)
{
    DPS_TxBufferFree(&ack->headers);
    DPS_TxBufferFree(&ack->payload);
    free(ack);
}

DPS_Status DPS_SendAcknowledgment(DPS_Node*node, PublicationAck* ack, RemoteNode* ackNode)
{
    DPS_Status ret;
    uv_buf_t uvBufs[] = {
        { (char*)ack->headers.base, DPS_TxBufferUsed(&ack->headers) },
        { (char*)ack->payload.base, DPS_TxBufferUsed(&ack->payload) }
    };

    DPS_DBGTRACE();
    /*
     * Ownership of the buffers has been passed to the network
     */
    ack->headers.base = NULL;
    ack->payload.base = NULL;
    ret = DPS_NetSend(node, NULL, &ackNode->ep, uvBufs, A_SIZEOF(uvBufs), DPS_OnSendComplete);
    if (ret != DPS_OK) {
        DPS_SendFailed(node, &ack->destAddr, uvBufs, A_SIZEOF(uvBufs), ret);
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

static DPS_Status GetKey(void* ctx, DPS_UUID* kid, int8_t alg, uint8_t key[AES_128_KEY_LEN])
{
    DPS_Node* node = (DPS_Node*)ctx;

    if (node->keyRequestCB) {
        return node->keyRequestCB(node, kid, key, AES_128_KEY_LEN);
    } else {
        return DPS_ERR_MISSING;
    }
}

static DPS_Status SerializeAck(DPS_Node* node, PublicationAck* ack, uint8_t* data, size_t dataLen)
{
    DPS_Status ret;
    uint8_t* aadPos;
    size_t len;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
    /*
     * Ack is encoded as an array of 3 elements
     *  [
     *      type,
     *      { body }
     *      payload (bstr)
     *  ]
     */
    len = CBOR_SIZEOF_ARRAY(3) +
          CBOR_SIZEOF(uint8_t) +

          CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF_BSTR(sizeof(DPS_UUID)) +
          CBOR_SIZEOF(uint32_t);

    ret = DPS_TxBufferInit(&ack->headers, NULL, len);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&ack->headers, 3);
    assert(ret == DPS_OK);
    ret = CBOR_EncodeUint8(&ack->headers, DPS_MSG_TYPE_ACK);
    assert(ret == DPS_OK);
    aadPos = ack->headers.txPos;
    ret = CBOR_EncodeMap(&ack->headers, 2);
    assert(ret == DPS_OK);
    ret = CBOR_EncodeUint8(&ack->headers, DPS_CBOR_KEY_PUB_ID);
    assert(ret == DPS_OK);
    ret = CBOR_EncodeBytes(&ack->headers, (uint8_t*)&ack->pubId, sizeof(ack->pubId));
    assert(ret == DPS_OK);
    ret = CBOR_EncodeUint8(&ack->headers, DPS_CBOR_KEY_SEQ_NUM);
    assert(ret == DPS_OK);
    ret = CBOR_EncodeUint32(&ack->headers, ack->sequenceNum);
    assert(ret == DPS_OK);

    ret = DPS_TxBufferInit(&ack->payload, NULL, CBOR_SIZEOF_BSTR(dataLen));
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeBytes(&ack->payload, data, dataLen);
    assert(ret == DPS_OK);
    /*
     * Check if the ack should be encrypted
     */
    if (node->isSecured) {
        DPS_RxBuffer aad;
        DPS_RxBuffer plainText;
        DPS_TxBuffer cipherText;
        uint8_t nonce[DPS_COSE_NONCE_SIZE];

        DPS_RxBufferInit(&aad, aadPos, ack->headers.txPos - aadPos);
        DPS_TxBufferToRx(&ack->payload, &plainText);

        DPS_MakeNonce(&ack->pubId, ack->sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        ret = COSE_Encrypt(AES_CCM_16_128_128, &node->keyId, nonce, &aad, &plainText, GetKey, node, &cipherText);
        DPS_TxBufferFree(&ack->payload);
        ack->payload = cipherText;
    }
    return ret;
}

DPS_Status DPS_DecodeAcknowledgment(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer)
{
    static const int32_t HeaderKeys[] = { DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_SEQ_NUM };
    DPS_Status ret;
    DPS_Publication* pub;
    CBOR_MapState mapState;
    uint32_t sn;
    uint32_t sequenceNum;
    DPS_UUID* pubId;
    DPS_NodeAddress* addr;
    uint8_t* aadPos = buffer->rxPos;
    size_t len;

    DPS_DBGTRACE();


    /*
     * Parse keys from body map
     */
    ret = DPS_ParseMapInit(&mapState, buffer, HeaderKeys, A_SIZEOF(HeaderKeys));
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Parse out the body fields
     */
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PUB_ID:
            ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
            if (ret == DPS_OK) {
                if (len != sizeof(DPS_UUID)) {
                    ret = DPS_ERR_INVALID;
                }
            }
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(buffer, &sequenceNum);
            if ((ret == DPS_OK) && (sequenceNum == 0)) {
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
        /*
         * Increase the refcount to prevent the publication from being
         * freed from inside the callback function
         */
        DPS_PublicationIncRef(pub);
        DPS_UnlockNode(node);
        if (pub->handler) {
            uint8_t nonce[DPS_COSE_NONCE_SIZE];
            DPS_RxBuffer payload;
            DPS_RxBuffer aad;
            DPS_RxBuffer cipherText;
            DPS_TxBuffer plainText;
            /*
             * Try to decrypt the acknowledgement
             */
            DPS_MakeNonce(pubId, sequenceNum, DPS_MSG_TYPE_ACK, nonce);
            DPS_RxBufferInit(&aad, aadPos, buffer->rxPos - aadPos);
            DPS_RxBufferInit(&cipherText, buffer->rxPos, DPS_RxBufferAvail(buffer));
            ret = COSE_Decrypt(nonce, &aad, &cipherText, GetKey, node, &plainText);
            if (ret == DPS_OK) {
                DPS_DBGPRINT("Ack was decrypted\n");
                DPS_TxBufferToRx(&plainText, &payload);
            } else if (ret == DPS_ERR_NOT_ENCRYPTED) {
                if (node->isSecured) {
                    DPS_ERRPRINT("Ack was not encrypted - discarding\n");
                } else {
                    payload = cipherText;
                    ret = DPS_OK;
                }
            } else {
                DPS_ERRPRINT("Failed to decrypt Ack - %s\n", DPS_ErrTxt(ret));
            }
            if (ret == DPS_OK) {
                uint8_t* data;
                size_t len;
                ret = CBOR_DecodeBytes(&payload, &data, &len);
                if (ret == DPS_OK) {
                    pub->handler(pub, data, len);
                }
            }
            DPS_TxBufferFree(&plainText);
        }
        DPS_LockNode(node);
        DPS_PublicationDecRef(pub);
        DPS_UnlockNode(node);
        return ret;
    }
    DPS_UnlockNode(node);
    /*
     * Search the history record for somewhere to forward the ACK
     */
    ret = DPS_LookupPublisher(&node->history, pubId, &sn, &addr);
    if ((ret == DPS_OK) && (sequenceNum <= sn) && addr) {
        RemoteNode* ackNode;
        ret = DPS_AddRemoteNode(node, addr, NULL, &ackNode);
        if (ret == DPS_OK) {
            uv_buf_t uvBuf;
            DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), sequenceNum, DPS_NodeAddrToString(addr));
            /*
             * The ACK is forwarded exactly as received
             */
            uvBuf.len = buffer->eod - buffer->base;
            uvBuf.base = malloc(uvBuf.len);
            if (uvBuf.base) {
                memcpy(uvBuf.base, buffer->base, uvBuf.len);
                ret = DPS_NetSend(node, NULL, &ackNode->ep, &uvBuf, 1, DPS_OnSendComplete);
                if (ret != DPS_OK) {
                    DPS_SendFailed(node, &ackNode->ep.addr, &uvBuf, 1, ret);
                }
            } else {
                ret = DPS_ERR_RESOURCES;
            }
        }
    };
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
    ret = SerializeAck(node, ack, payload, len);
    if (ret == DPS_OK) {
        ack->destAddr = *addr;
        DPS_QueuePublicationAck(node, ack);
    } else {
        DPS_DestroyAck(ack);
    }
    return ret;
}

