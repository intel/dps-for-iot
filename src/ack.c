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

static PublicationAck* CreateAck(const DPS_Publication* pub, size_t numBufs,
                                 DPS_AckPublicationBufsComplete cb, void* data)
{
    PublicationAck* ack = NULL;

    /*
     * Reserve additional buffers for the authenticated fields,
     * optional COSE headers, payload headers, and optional COSE
     * footers.
     */
    numBufs += NUM_INTERNAL_ACK_BUFS;
    ack = calloc(1, sizeof(PublicationAck) + ((numBufs - 1) * sizeof(DPS_TxBuffer)));
    if (!ack) {
        return NULL;
    }
    ack->pub = (DPS_Publication*)pub;
    DPS_PublicationIncRef(ack->pub);
    ack->sequenceNum = pub->sequenceNum;
    ack->completeCB = cb;
    ack->data = data;
    ack->numBufs = numBufs;
    return ack;
}

static void DestroyAck(PublicationAck* ack)
{
    if (ack) {
        DPS_TxBufferFree(&ack->bufs[0]);
        DPS_TxBufferFree(&ack->bufs[1]);
        DPS_TxBufferFree(&ack->bufs[2]);
        DPS_TxBufferFree(&ack->bufs[ack->numBufs - 1]);
        /*
         * Any additional buffers belong to the application
         */
        DPS_PublicationDecRef(ack->pub);
        free(ack);
    }
}

void DPS_AckPublicationCompletion(PublicationAck* ack)
{
    DPS_Buffer bufs[DPS_BUFS_MAX];
    size_t numBufs = 0;
    size_t i;

    if (ack->completeCB) {
        if (ack->numBufs > NUM_INTERNAL_ACK_BUFS) {
            numBufs = ack->numBufs - NUM_INTERNAL_ACK_BUFS;
            for (i = 0; i < numBufs; ++i) {
                bufs[i].base = ack->bufs[i + 3].base;
                bufs[i].len = DPS_TxBufferUsed(&ack->bufs[i + 3]);
            }
        }
        ack->completeCB(ack->pub, numBufs ? bufs : NULL, numBufs, ack->status, ack->data);
    }
    DestroyAck(ack);
}

static void SendComplete(PublicationAck* ack, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    ack->status = status;
    DPS_SendComplete(ack->pub->node, &ack->destAddr, NULL, 0, status);
    DPS_AckPublicationCompletion(ack);
}

static void OnNetSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs,
                              size_t numBufs, DPS_Status status)
{
    PublicationAck* ack = appCtx;

    DPS_LockNode(node);
    SendComplete(ack, bufs, numBufs, status);
    DPS_UnlockNode(node);
}

DPS_Status DPS_SendAcknowledgement(PublicationAck* ack, RemoteNode* ackNode)
{
    DPS_Node* node = ack->pub->node;
    uv_buf_t uvBufs[NUM_INTERNAL_ACK_BUFS + DPS_BUFS_MAX];
    int loopback = DPS_FALSE;
    DPS_Publication* pub;
    DPS_Status ret;
    size_t i;

    DPS_DBGPRINT("SendAcknowledgement from %s to %s\n", node->addrStr,
                 DPS_NodeAddrToString(&ackNode->ep.addr));

    for (i = 0; i < ack->numBufs; ++i) {
        uvBufs[i] = uv_buf_init((char*)ack->bufs[i].base, DPS_TxBufferUsed(&ack->bufs[i]));
    };

    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_LOCAL) && (DPS_UUIDCompare(&pub->pubId, &ack->pub->pubId) == 0)) {
            loopback = DPS_TRUE;
            break;
        }
    }

    if (loopback) {
        ret = DPS_LoopbackSend(node, uvBufs, ack->numBufs);
        SendComplete(ack, uvBufs, ack->numBufs, ret);
    } else {
        ret = DPS_NetSend(node, ack, &ackNode->ep, uvBufs, ack->numBufs, OnNetSendComplete);
        if (ret != DPS_OK) {
            SendComplete(ack, uvBufs, ack->numBufs, ret);
        }
    }
    /*
     * Return DPS_OK as the ack request has been (or will be)
     * completed now
     */
    return DPS_OK;
}

static DPS_Status SerializeAck(const DPS_Publication* pub, PublicationAck* ack, const DPS_Buffer* bufs,
                               size_t numBufs)
{
    DPS_Node* node = pub->node;
    DPS_Status ret;
    uint8_t* aadPos;
    size_t dataLen;
    size_t len;
    size_t i;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);
    assert(ack->numBufs == numBufs + NUM_INTERNAL_ACK_BUFS);

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
        ret = CBOR_EncodeBytes(&ack->bufs[0], (uint8_t*)&ack->pub->pubId, sizeof(ack->pub->pubId));
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
    dataLen = 0;
    for (i = 0; i < numBufs; ++i) {
        dataLen += bufs[i].len;
    }
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(1) + CBOR_SIZEOF(uint8_t) +
            CBOR_SIZEOF_LEN(dataLen);
        ret = DPS_TxBufferInit(&ack->bufs[2], NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&ack->bufs[2], 1);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&ack->bufs[2], DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeLength(&ack->bufs[2], dataLen, CBOR_BYTES);
    }
    for (i = 0; (ret == DPS_OK) && (i < numBufs); ++i) {
        ack->bufs[i + 3].base = bufs[i].base;
        ack->bufs[i + 3].eob = bufs[i].base + bufs[i].len;
        ack->bufs[i + 3].txPos = ack->bufs[i + 3].eob;
    }
    DPS_TxBufferClear(&ack->bufs[ack->numBufs - 1]);
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
        DPS_MakeNonce(&ack->pub->pubId, ack->sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        if (pub->recipients) {
            ret = COSE_Encrypt(COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                               pub->recipients, pub->recipientsCount, &aadBuf, &ack->bufs[1],
                               &ack->bufs[2], ack->numBufs - 3, &ack->bufs[ack->numBufs - 1],
                               node->keyStore);
        } else {
            ret = COSE_Sign(&node->signer, &aadBuf, &ack->bufs[1], &ack->bufs[2], ack->numBufs - 3,
                            &ack->bufs[ack->numBufs - 1], node->keyStore);
        }
        if (ret != DPS_OK) {
            DPS_WARNPRINT("COSE_Serialize failed: %s\n", DPS_ErrTxt(ret));
        }
    }
    return ret;
}

static void OnSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs,
                           DPS_Status status)
{
    DPS_LockNode(node);
    DPS_SendComplete(node, ep ? &ep->addr : NULL, NULL, 0, status);
    DPS_UnlockNode(node);
}

DPS_Status DPS_DecodeAcknowledgement(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf)
{
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_ACK_SEQ_NUM };
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_DATA };
    DPS_RxBuffer* rxBuf = (DPS_RxBuffer*)buf;
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
    ret = CBOR_Skip(rxBuf, &maj, &len);
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
    aadPos = rxBuf->rxPos;
    ret = DPS_ParseMapInit(&mapState, rxBuf, ProtectedKeys, A_SIZEOF(ProtectedKeys), NULL, 0);
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
            ret = CBOR_DecodeBytes(rxBuf, &bytes, &len);
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
            ret = CBOR_DecodeUint32(rxBuf, &sequenceNum);
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
        DPS_RxBufferInit(&aadBuf, aadPos, rxBuf->rxPos - aadPos);
        DPS_RxBufferInit(&cipherTextBuf, rxBuf->rxPos, DPS_RxBufferAvail(rxBuf));
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
                    pub->rxBuf = buf;
                }
            } else {
                ret = DPS_ERR_INVALID;
                DPS_ERRPRINT("Invalid COSE object for Ack - %s\n", DPS_ErrTxt(ret));
            }
        } else {
            DPS_DBGPRINT("Ack was not a COSE object\n");
            encryptedBuf = cipherTextBuf;
            pub->rxBuf = buf;
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
        pub->rxBuf = NULL;
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
            uvBuf = uv_buf_init((char*)rxBuf->base, (uint32_t)(rxBuf->eod - rxBuf->base));
            ret = DPS_NetSend(node, NULL, &ackNode->ep, &uvBuf, 1, OnSendComplete);
            if (ret == DPS_OK) {
                DPS_NetRxBufferIncRef(buf);
            } else {
                DPS_SendComplete(node, &ackNode->ep.addr, NULL, 0, ret);
            }
        }
        DPS_UnlockNode(node);
    }
    return ret;
}

DPS_Status DPS_AckPublicationBufs(const DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                                  DPS_AckPublicationBufsComplete cb, void* data)
{
    DPS_Status ret;
    DPS_NodeAddress* addr = NULL;
    DPS_Node* node = pub ? pub->node : NULL;
    uint32_t unused;
    PublicationAck* ack;

    DPS_DBGTRACE();

    if (!node) {
        return DPS_ERR_NULL;
    }
    if (pub->flags & PUB_FLAG_LOCAL) {
        return DPS_ERR_INVALID;
    }
    if ((!bufs && numBufs) || (numBufs > DPS_BUFS_MAX)) {
        return DPS_ERR_ARGS;
    }
    ret = DPS_LookupPublisherForAck(&node->history, &pub->pubId, &unused, &addr);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!addr) {
        return DPS_ERR_NO_ROUTE;
    }
    DPS_DBGPRINT("Queueing acknowledgement for %s/%d to %s\n", DPS_UUIDToString(&pub->pubId),
                 pub->sequenceNum, DPS_NodeAddrToString(addr));
    ack = CreateAck(pub, numBufs, cb, data);
    if (!ack) {
        return DPS_ERR_RESOURCES;
    }
    ret = SerializeAck(pub, ack, bufs, numBufs);
    if (ret == DPS_OK) {
        ack->destAddr = *addr;
        DPS_QueuePublicationAck(node, ack);
    } else {
        DestroyAck(ack);
    }
    return ret;
}

static void AckPublicationComplete(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                                   DPS_Status status, void* data)
{
    if (numBufs && bufs[0].base) {
        free(bufs[0].base);
    }
}

DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* data, size_t dataLen)
{
    DPS_Status ret;
    DPS_Buffer buf = { NULL, 0 };
    DPS_Buffer* bufs = NULL;
    size_t numBufs = 0;

    DPS_DBGTRACE();

    if (data && dataLen) {
        buf.base = malloc(dataLen);
        if (!buf.base) {
            return DPS_ERR_RESOURCES;
        }
        memcpy(buf.base, data, dataLen);
        buf.len = dataLen;
        bufs = &buf;
        numBufs = 1;
    }
    ret = DPS_AckPublicationBufs(pub, bufs, numBufs, AckPublicationComplete, NULL);
    if (ret != DPS_OK) {
        free(buf.base);
    }
    return ret;
}
