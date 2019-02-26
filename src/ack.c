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
#include "ack.h"
#include "bitvec.h"
#include "coap.h"
#include "history.h"
#include "node.h"
#include "pub.h"
#include "topics.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

void DPS_DestroyAck(PublicationAck* ack)
{
    size_t i;

    for (i = 0; i < ACK_BUFS_MAX; ++i) {
        DPS_TxBufferFree(&ack->bufs[i]);
    }
    free(ack);
}

DPS_Status DPS_SendAcknowledgement(DPS_Node* node, PublicationAck* ack, RemoteNode* ackNode)
{
    uv_buf_t uvBufs[ACK_BUFS_MAX];
    int loopback = DPS_FALSE;
    DPS_Publication* pub;
    DPS_Status ret;
    size_t i;

    DPS_DBGPRINT("SendAcknowledgement from %d to %s\n", node->port, DPS_NodeAddrToString(&ackNode->ep.addr));

    for (i = 0; i < ACK_BUFS_MAX; ++i) {
        uvBufs[i] = uv_buf_init((char*)ack->bufs[i].base, DPS_TxBufferUsed(&ack->bufs[i]));
    };

    /*
     * Ownership of the buffers will be passed to the network
     */
    for (i = 0; i < ACK_BUFS_MAX; ++i) {
        ack->bufs[i].base = NULL;
    }

    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (DPS_UUIDCompare(&pub->pubId, &ack->pubId) == 0) {
            loopback = DPS_TRUE;
            break;
        }
    }

    if (loopback) {
        ret = DPS_LoopbackSend(node, uvBufs, A_SIZEOF(uvBufs));
        if (ret == DPS_OK) {
            DPS_NetFreeBufs(uvBufs, A_SIZEOF(uvBufs));
        } else {
            DPS_SendComplete(node, &ack->destAddr, uvBufs, A_SIZEOF(uvBufs), ret);
        }
    } else {
        ret = DPS_NetSend(node, NULL, &ackNode->ep, uvBufs, A_SIZEOF(uvBufs), DPS_OnSendComplete);
        if (ret != DPS_OK) {
            DPS_SendComplete(node, &ack->destAddr, uvBufs, A_SIZEOF(uvBufs), ret);
        }
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

static DPS_Status SerializeAck(const DPS_Publication* pub, PublicationAck* ack, const uint8_t* data,
                               size_t dataLen)
{
    DPS_Node* node = pub->node;
    DPS_Status ret;
    uint8_t* aadPos;
    size_t len;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    len = CBOR_SIZEOF_ARRAY(5) +
          CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
          CBOR_SIZEOF(uint32_t);
    ret = DPS_TxBufferInit(&ack->bufs[0], NULL, len);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&ack->bufs[0], 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[0], DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[0], DPS_MSG_TYPE_ACK);
    }
    /*
     * Encode the (empty) unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->bufs[0], 0);
    }
    /*
     * Encode the protected map
     */
    aadPos = ack->bufs[0].txPos;
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->bufs[0], 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[0], DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&ack->bufs[0], (uint8_t*)&ack->pubId, sizeof(ack->pubId));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[0], DPS_CBOR_KEY_ACK_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&ack->bufs[0], ack->sequenceNum);
    }
    /*
     * Encode the encrypted map
     */
    DPS_TxBufferClear(&ack->bufs[1]);
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(1) + CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF_BYTES(dataLen);
        ret = DPS_TxBufferInit(&ack->bufs[2], NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->bufs[2], 1);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[2], DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&ack->bufs[2], data, dataLen);
    }
    DPS_TxBufferClear(&ack->bufs[3]);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * If the publication was encrypted the ack must be too
     */
    if (pub->recipients || node->signer.alg) {
        DPS_RxBuffer aadBuf;
        uint8_t nonce[COSE_NONCE_LEN];

        DPS_RxBufferInit(&aadBuf, aadPos, ack->bufs[0].txPos - aadPos);
        DPS_MakeNonce(&ack->pubId, ack->sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        if (pub->recipients) {
            ret = COSE_Encrypt(COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                               pub->recipients, pub->recipientsCount, &aadBuf, &ack->bufs[1],
                               &ack->bufs[2], 1, &ack->bufs[3], node->keyStore);
        } else {
            ret = COSE_Sign(&node->signer, &aadBuf, &ack->bufs[1], &ack->bufs[2], 1, &ack->bufs[3],
                            node->keyStore);
        }
        if (ret != DPS_OK) {
            DPS_WARNPRINT("COSE_Serialize failed: %s\n", DPS_ErrTxt(ret));
        }
    }
    return ret;
}

DPS_Status DPS_DecodeAcknowledgement(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buf)
{
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_ACK_SEQ_NUM };
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_DATA };
    DPS_Status ret;
    DPS_Publication* pub;
    CBOR_MapState mapState;
    uint32_t sn;
    uint32_t sequenceNum;
    uint8_t* bytes = NULL;
    DPS_UUID pubId;
    DPS_NodeAddress* addr;
    uint8_t* aadPos;
    uint8_t maj;
    size_t len;

    DPS_DBGTRACE();

    /*
     * Skip the (empty) unprotected map
     */
    ret = CBOR_Skip(buf, &maj, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (maj != CBOR_MAP) {
        ret = DPS_ERR_INVALID;
        return ret;
    }
    /*
     * Decode the protected map
     */
    aadPos = buf->rxPos;
    ret = DPS_ParseMapInit(&mapState, buf, ProtectedKeys, A_SIZEOF(ProtectedKeys), NULL, 0);
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
        case DPS_CBOR_KEY_PUB_ID:
            ret = CBOR_DecodeBytes(buf, &bytes, &len);
            if (ret == DPS_OK) {
                if (len != sizeof(DPS_UUID)) {
                    ret = DPS_ERR_INVALID;
                }
            }
            if (ret == DPS_OK) {
                memcpy(&pubId.val, bytes, sizeof(DPS_UUID));
            }
            break;
        case DPS_CBOR_KEY_ACK_SEQ_NUM:
            ret = CBOR_DecodeUint32(buf, &sequenceNum);
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
    pub = DPS_LookupAckHandler(node, &pubId, sequenceNum);
    if (pub) {
        uint8_t nonce[COSE_NONCE_LEN];
        COSE_Entity unused;
        DPS_RxBuffer encryptedBuf;
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer cipherTextBuf;
        DPS_TxBuffer plainTextBuf;
        uint8_t type;
        uint64_t tag;
        /*
         * Increase the refcount to prevent the publication from being
         * freed from inside the callback function
         */
        DPS_PublicationIncRef(pub);
        DPS_UnlockNode(node);
        /*
         * Try to decrypt the acknowledgement
         */
        DPS_MakeNonce(&pubId, sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        DPS_RxBufferInit(&aadBuf, aadPos, buf->rxPos - aadPos);
        DPS_RxBufferInit(&cipherTextBuf, buf->rxPos, DPS_RxBufferAvail(buf));
        DPS_TxBufferClear(&plainTextBuf);
        ret = CBOR_Peek(&cipherTextBuf, &type, &tag);
        if ((ret == DPS_OK) && (type == CBOR_TAG)) {
            if ((tag == COSE_TAG_ENCRYPT0) || (tag == COSE_TAG_ENCRYPT)) {
                ret = COSE_Decrypt(nonce, &unused, &aadBuf, &cipherTextBuf, node->keyStore, &pub->ack,
                                   &plainTextBuf);
                if (ret == DPS_OK) {
                    DPS_DBGPRINT("Ack was COSE decrypted\n");
                    CBOR_Dump("plaintext", plainTextBuf.base, DPS_TxBufferUsed(&plainTextBuf));
                    DPS_TxBufferToRx(&plainTextBuf, &encryptedBuf);
                }
            } else if (tag == COSE_TAG_SIGN1) {
                ret = COSE_Verify(&aadBuf, &cipherTextBuf, node->keyStore, &pub->ack);
                if (ret == DPS_OK) {
                    DPS_DBGPRINT("Ack was COSE verified\n");
                    encryptedBuf = cipherTextBuf;
                }
            } else {
                ret = DPS_ERR_INVALID;
                DPS_ERRPRINT("Invalid COSE object for Ack - %s\n", DPS_ErrTxt(ret));
            }
        } else {
            DPS_DBGPRINT("Ack was not a COSE object\n");
            encryptedBuf = cipherTextBuf;
            ret = DPS_OK;
        }
        if (ret == DPS_OK) {
            uint8_t* data = NULL;
            size_t dataLen = 0;
            ret = DPS_ParseMapInit(&mapState, &encryptedBuf, EncryptedKeys, A_SIZEOF(EncryptedKeys), NULL, 0);
            if (ret == DPS_OK) {
                while (!DPS_ParseMapDone(&mapState)) {
                    int32_t key;
                    ret = DPS_ParseMapNext(&mapState, &key);
                    if (ret != DPS_OK) {
                        break;
                    }
                    switch (key) {
                    case DPS_CBOR_KEY_DATA:
                        /*
                         * Get the pointer to the ack data
                         */
                        ret = CBOR_DecodeBytes(&encryptedBuf, &data, &dataLen);
                        break;
                    }
                    if (ret != DPS_OK) {
                        break;
                    }
                }
                if (ret == DPS_OK) {
                    pub->handler(pub, data, dataLen);
                }
            }
        }
        DPS_TxBufferFree(&plainTextBuf);
        /* Ack ID will be invalid now */
        memset(&pub->ack, 0, sizeof(pub->ack));
        DPS_LockNode(node);
        DPS_PublicationDecRef(pub);
        DPS_UnlockNode(node);
        return ret;
    }
    DPS_UnlockNode(node);
    /*
     * Search the history record for somewhere to forward the ACK
     */
    ret = DPS_LookupPublisherForAck(&node->history, &pubId, &sn, &addr);
    if ((ret == DPS_OK) && (sequenceNum <= sn) && addr && !DPS_SameAddr(&ep->addr, addr)) {
        RemoteNode* ackNode;
        DPS_LockNode(node);
        ret = DPS_AddRemoteNode(node, addr, NULL, &ackNode);
        if (ret == DPS_OK || ret == DPS_ERR_EXISTS) {
            uv_buf_t uvBuf;
            DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(&pubId), sequenceNum, DPS_NodeAddrToString(addr));
            /*
             * The ACK is forwarded exactly as received
             */
            uvBuf.len = (uint32_t)(buf->eod - buf->base);
            uvBuf.base = malloc(uvBuf.len);
            if (uvBuf.base) {
                memcpy_s(uvBuf.base, uvBuf.len, buf->base, uvBuf.len);
                ret = DPS_NetSend(node, NULL, &ackNode->ep, &uvBuf, 1, DPS_OnSendComplete);
                if (ret != DPS_OK) {
                    DPS_SendComplete(node, &ackNode->ep.addr, &uvBuf, 1, ret);
                }
            } else {
                ret = DPS_ERR_RESOURCES;
            }
        }
        DPS_UnlockNode(node);
    }
    return ret;
}

DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* data, size_t dataLen)
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
    ret = DPS_LookupPublisherForAck(&node->history, &pub->pubId, &sequenceNum, &addr);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!addr) {
        return DPS_ERR_NO_ROUTE;
    }
    DPS_DBGPRINT("Queueing acknowledgement for %s/%d to %s\n", DPS_UUIDToString(&pub->pubId),
                 pub->sequenceNum, DPS_NodeAddrToString(addr));
    ack = AllocPubAck(&pub->pubId, pub->sequenceNum);
    if (!ack) {
        return DPS_ERR_RESOURCES;
    }
    ret = SerializeAck(pub, ack, data, dataLen);
    if (ret == DPS_OK) {
        ack->destAddr = *addr;
        DPS_QueuePublicationAck(node, ack);
    } else {
        DPS_DestroyAck(ack);
    }
    return ret;
}

