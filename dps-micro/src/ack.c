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
#include <dps/private/node.h>
#include <dps/private/pub.h>
#include <dps/private/sub.h>
#include <dps/private/network.h>
#include <dps/private/bitvec.h>
#include <dps/private/topics.h>
#include <dps/private/cbor.h>
#include <dps/private/coap.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_Status DPS_SendAcknowledgement(DPS_Node* node, PublicationAck* ack, RemoteNode* ackNode)
{
    uv_buf_t uvBufs[] = {
        uv_buf_init((char*)ack->buf.base, DPS_TxBufferUsed(&ack->buf)),
        uv_buf_init((char*)ack->encryptedBuf.base, DPS_TxBufferUsed(&ack->encryptedBuf))
    };
    int loopback = DPS_FALSE;
    DPS_Publication* pub;
    DPS_Status ret;

    DPS_DBGPRINT("SendAcknowledgement from %d to %s\n", node->port, DPS_NodeAddrToString(&ackNode->ep.addr));

    /*
     * Ownership of the buffers will be passed to the network
     */
    ack->buf.base = NULL;
    ack->encryptedBuf.base = NULL;

    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (DPS_UUIDCompare(&pub->shared->pubId, &ack->pubId) == 0) {
            loopback = DPS_TRUE;
            break;
        }
    }

    if (loopback) {
        ret = DPS_LoopbackSend(node, uvBufs, A_SIZEOF(uvBufs));
        if (ret == DPS_OK) {
            DPS_NetFreeBufs(uvBufs, A_SIZEOF(uvBufs));
        } else {
            DPS_SendFailed(node, &ack->destAddr, uvBufs, A_SIZEOF(uvBufs), ret);
        }
    } else {
        ret = DPS_NetSend(node, NULL, &ackNode->ep, uvBufs, A_SIZEOF(uvBufs), DPS_OnSendComplete);
        if (ret != DPS_OK) {
            DPS_SendFailed(node, &ack->destAddr, uvBufs, A_SIZEOF(uvBufs), ret);
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

static DPS_Status SerializeAck(const DPS_Publication* pub, PublicationAck* ack, const uint8_t* data, size_t dataLen)
{
    DPS_Node* node = pub->shared->node;
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
    ret = DPS_TxBufferInit(&ack->buf, NULL, len);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&ack->buf, 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->buf, DPS_MSG_TYPE_ACK);
    }
    /*
     * Encode the (empty) unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->buf, 0);
    }
    /*
     * Encode the protected map
     */
    aadPos = ack->buf.txPos;
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->buf, 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->buf, DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&ack->buf, (uint8_t*)&ack->pubId, sizeof(ack->pubId));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->buf, DPS_CBOR_KEY_ACK_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&ack->buf, ack->sequenceNum);
    }
    /*
     * Encode the encrypted map
     */
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(1) + CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF_BYTES(dataLen);
        ret = DPS_TxBufferInit(&ack->encryptedBuf, NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->encryptedBuf, 1);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->encryptedBuf, DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&ack->encryptedBuf, data, dataLen);
    }
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * If the publication was encrypted the ack must be too
     */
    if (pub->shared->recipients) {
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer plainTextBuf;
        DPS_TxBuffer cipherTextBuf;
        uint8_t nonce[COSE_NONCE_LEN];

        DPS_RxBufferInit(&aadBuf, aadPos, ack->buf.txPos - aadPos);
        DPS_TxBufferToRx(&ack->encryptedBuf, &plainTextBuf);
        DPS_MakeNonce(&ack->pubId, ack->sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        ret = COSE_Encrypt(COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                           pub->shared->recipients, pub->shared->recipientsCount, &aadBuf, &plainTextBuf,
                           node->keyStore, &cipherTextBuf);
        DPS_TxBufferFree(&ack->encryptedBuf);
        if (ret == DPS_OK) {
            ack->encryptedBuf = cipherTextBuf;
        } else {
            DPS_WARNPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
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
        COSE_Entity recipient;
        DPS_RxBuffer encryptedBuf;
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer cipherTextBuf;
        DPS_TxBuffer plainTextBuf;
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
        ret = COSE_Decrypt(nonce, &recipient, &aadBuf, &cipherTextBuf, node->keyStore,
                           &pub->shared->ack, &plainTextBuf);
        if (ret == DPS_OK) {
            DPS_DBGPRINT("Ack was decrypted\n");
            CBOR_Dump("plaintext", plainTextBuf.base, DPS_TxBufferUsed(&plainTextBuf));
            DPS_TxBufferToRx(&plainTextBuf, &encryptedBuf);
        } else if (ret == DPS_ERR_NOT_ENCRYPTED) {
            DPS_DBGPRINT("Ack was not encrypted\n");
            encryptedBuf = cipherTextBuf;
            ret = DPS_OK;
        } else {
            DPS_ERRPRINT("Failed to decrypt Ack - %s\n", DPS_ErrTxt(ret));
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
                    pub->shared->handler(pub, data, dataLen);
                }
            }
        }
        DPS_TxBufferFree(&plainTextBuf);
        /* Ack ID will be invalid now */
        memset(&pub->shared->ack, 0, sizeof(pub->shared->ack));
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
                    DPS_SendFailed(node, &ackNode->ep.addr, &uvBuf, 1, ret);
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
    uint32_t sequenceNum;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    if (pub->ackRequested) {
        return DPS_ERR_INVALID;
    }

    /* Free the Tx buffer pools */
    DPS_TxBufferFreePool(pub->node, DPS_TX_POOL);
    DPS_TxBufferFreePool(pub->node, DPS_TX_HDR_POOL);
    DPS_TxBufferFreePool(pub->node, DPS_TMP_POOL);

    DPS_DBGPRINT("Sending ack for %s/%d\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum);

    ret = SerializeAck(pub, data, dataLen);
    if (ret == DPS_OK) {
        ack->destAddr = *addr;
        DPS_QueuePublicationAck(node, ack);
    } else {
        DPS_DestroyAck(ack);
    }
    return ret;
}

