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
#include <dps/private/ack.h>
#include <dps/private/pub.h>
#include <dps/private/network.h>
#include <dps/private/topics.h>
#include <dps/private/cbor.h>
#include <dps/private/coap.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static DPS_Status SerializeAck(const DPS_Publication* pub, const uint8_t* data, size_t dataLen)
{
    DPS_Node* node = pub->node;
    DPS_Status ret;
    size_t len;
    DPS_TxBuffer buf;
    DPS_TxBuffer protectedBuf;
    DPS_TxBuffer encryptedBuf;

    DPS_DBGTRACE();

    len = CBOR_SIZEOF_ARRAY(5) +
          CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF_MAP(0);

    ret = DPS_TxBufferReserve(node, &buf, len, DPS_TX_POOL);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeArray(&buf, 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_ACK);
    }
    /*
     * Encode the (empty) unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 0);
    }
    DPS_TxBufferCommit(&buf);

    len = CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
          CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
          CBOR_SIZEOF(uint32_t);
    /*
     * Encode the protected map
     */
    ret = DPS_TxBufferReserve(node, &protectedBuf, len, DPS_TX_POOL);
    if (ret != DPS_OK) {
        return ret;
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&protectedBuf, 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&protectedBuf, (uint8_t*)&pub->pubId, sizeof(DPS_UUID));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_ACK_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&protectedBuf, pub->sequenceNum);
    }
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_TxBufferCommit(&protectedBuf);
    /*
     * Encode the encrypted map
     */
    len = CBOR_SIZEOF_MAP(1) + CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF_BYTES(dataLen);
    /*
     * If the data is not encrypted can be serialized directly into the TX pool
     * otherwise it is serialized into the TMP pool.
     */
    ret = DPS_TxBufferReserve(node, &buf, len, (pub->numRecipients > 0) ? DPS_TMP_POOL : DPS_TX_POOL);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_EncodeMap(&buf, 1);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&buf, data, dataLen);
    }
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * If the publication was encrypted the ack must be too
     */
    if (pub->recipients) {
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer plainTextBuf;
        uint8_t nonce[COSE_NONCE_LEN];

        DPS_DBGPRINT("Encrypting Ack\n");
        DPS_TxBufferToRx(&buf, &plainTextBuf);
        DPS_TxBufferToRx(&protectedBuf, &aadBuf);
        DPS_MakeNonce(&pub->pubId, pub->sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        ret = COSE_Encrypt(node, COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                pub->recipients, pub->numRecipients, &aadBuf, &plainTextBuf, node->keyStore, &encryptedBuf);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
        DPS_DBGPRINT("Ack was encrypted\n");
        CBOR_Dump("aad", aadBuf.base, DPS_RxBufferAvail(&aadBuf));
        CBOR_Dump("cryptText", encryptedBuf.base, DPS_TxBufferUsed(&encryptedBuf));
    } else {
        DPS_TxBufferCommit(&buf);
    }
    return ret;
}

DPS_Status DPS_DecodeAcknowledgement(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf)
{
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_ACK_SEQ_NUM };
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_DATA };
    DPS_Status ret;
    DPS_Publication* pub;
    CBOR_MapState mapState;
    uint32_t sequenceNum;
    uint8_t* bytes = NULL;
    DPS_UUID pubId;
    uint8_t* aadPos;
    uint8_t maj;
    size_t len;

    DPS_DBGTRACE();

    CBOR_Dump("Ack in", buf->rxPos, DPS_RxBufferAvail(buf));

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
    /*
     * See if this is an ACK we expected
     */
    pub = DPS_LookupAckHandler(node, &pubId, sequenceNum);
    if (pub) {
        uint8_t nonce[COSE_NONCE_LEN];
        COSE_Entity recipient;
        DPS_TxBuffer outBuf;
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer cipherTextBuf;
        /*
         * Try to decrypt the acknowledgement
         */
        DPS_MakeNonce(&pubId, sequenceNum, DPS_MSG_TYPE_ACK, nonce);
        DPS_RxBufferInit(&aadBuf, aadPos, buf->rxPos - aadPos);
        DPS_RxBufferInit(&cipherTextBuf, buf->rxPos, DPS_RxBufferAvail(buf));
        /* 
         * Decrypt into the temporary pool
         */
        ret = DPS_TxBufferReserve(node, &outBuf, DPS_RxBufferAvail(&cipherTextBuf), DPS_TMP_POOL);
        if (ret != DPS_OK) {
            return ret;
        }
        ret = COSE_Decrypt(node, nonce, &recipient, &aadBuf, &cipherTextBuf, node->keyStore, &pub->ack, &outBuf);
        if (ret == DPS_OK) {
            DPS_DBGPRINT("Ack was decrypted\n");
            CBOR_Dump("plaintext", outBuf.base, DPS_TxBufferUsed(&outBuf));
            DPS_TxBufferToRx(&outBuf, buf);
        } else if (ret == DPS_ERR_NOT_ENCRYPTED) {
            DPS_DBGPRINT("Ack was not encrypted\n");
            *buf = cipherTextBuf;
            ret = DPS_OK;
        } else {
            DPS_ERRPRINT("Failed to decrypt Ack - %s\n", DPS_ErrTxt(ret));
        }
        if (ret == DPS_OK) {
            uint8_t* data = NULL;
            size_t dataLen = 0;
            ret = DPS_ParseMapInit(&mapState, buf, EncryptedKeys, A_SIZEOF(EncryptedKeys), NULL, 0);
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
                        ret = CBOR_DecodeBytes(buf, &data, &dataLen);
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
    }
    return ret;
}

DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* data, size_t dataLen)
{
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    if (!pub->ackRequested) {
        return DPS_ERR_INVALID;
    }

    /* Free the Tx buffer pools */
    DPS_TxBufferFreePool(pub->node, DPS_TX_POOL);
    DPS_TxBufferFreePool(pub->node, DPS_TX_HDR_POOL);
    DPS_TxBufferFreePool(pub->node, DPS_TMP_POOL);

    DPS_DBGPRINT("Sending ack for %s/%d\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum);

    ret = SerializeAck(pub, data, dataLen);
    if (ret == DPS_OK) {
        ret = DPS_UnicastSend(pub->node, pub->sendAddr, NULL, NULL);
    }
    return ret;
}

