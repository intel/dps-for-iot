/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
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
#include <safe_lib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include <dps/private/bitvec.h>
#include <dps/private/cbor.h>
#include <dps/compat.h>
#include <dps/private/cose.h>
#include <dps/private/coap.h>
#include <dps/private/pub.h>
#include <dps/private/topics.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static DPS_Status SetKey(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    int8_t* alg = request->data;

    switch (key->type) {
    case DPS_KEY_SYMMETRIC:
        *alg = COSE_ALG_A256KW;
        break;
    case DPS_KEY_EC:
    case DPS_KEY_EC_CERT:
        *alg = COSE_ALG_ECDH_ES_A256KW;
        break;
    default:
    }
    return DPS_OK;
}

static DPS_Status GetRecipientAlgorithm(DPS_KeyStore* keyStore, const DPS_KeyId* kid, int8_t* alg)
{
    DPS_KeyStoreRequest request;

    *alg = COSE_ALG_RESERVED;
    if (!keyStore || !keyStore->keyHandler) {
        return DPS_ERR_MISSING;
    }
    memset(&request, 0, sizeof(request));
    request.keyStore = keyStore;
    request.data = alg;
    request.setKey = SetKey;
    return keyStore->keyHandler(&request, kid);
}

static COSE_Entity* AddRecipient(DPS_Publication* pub, int8_t alg, const DPS_KeyId* kid)
{
    COSE_Entity* recipient;

    if (pub->numRecipients == MAX_PUB_RECIPIENTS) {
        return NULL;
    }
    recipient = &pub->recipients[pub->numRecipients++];
    recipient->alg = alg;
    memcpy(&recipient->kid, kid, sizeof(DPS_KeyId));
    ++pub->recipientsCount;
    return recipient;
}

static void RemoveRecipient(DPS_Publication* pub, const DPS_KeyId* kid)
{
    size_t i;

    for (i = 0; i < pub->recipientsCount; ++i) {
        if ((pub->recipients[i].kid.len == kid->len) &&
            (memcmp(&pub->recipients[i].kid.id, &kid->id, kid->len) == 0)) {
            DPS_ClearKeyId(&pub->recipients[i].kid);
            for (; i < pub->recipientsCount - 1; ++i) {
                pub->recipients[i] = pub->recipients[i + 1];
            }
            memset(&pub->recipients[i], 0, sizeof(pub->recipients[i]));
            --pub->recipientsCount;
            break;
        }
    }
}

const DPS_UUID* DPS_PublicationGetUUID(const DPS_Publication* pub)
{
    if (pub) {
        return &pub->pubId;
    } else {
        return NULL;
    }
}

uint32_t DPS_PublicationGetSequenceNum(const DPS_Publication* pub)
{
    if (pub) {
        return pub->sequenceNum;
    } else {
        return 0;
    }
}

size_t DPS_PublicationGetNumTopics(const DPS_Publication* pub)
{
    if (pub) {
        return pub->numTopics;
    } else {
        return 0;
    }
}

const char* DPS_PublicationGetTopic(const DPS_Publication* pub, size_t index)
{
    if (pub && (pub->numTopics > index)) {
        return pub->topics[index];
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_PublicationGetSenderKeyId(const DPS_Publication* pub)
{
    if (pub && (pub->sender.alg != COSE_ALG_RESERVED)) {
        return &pub->sender.kid;
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_AckGetSenderKeyId(const DPS_Publication* pub)
{
    if (pub && (pub->ack.alg != COSE_ALG_RESERVED)) {
        return &pub->ack.kid;
    } else {
        return NULL;
    }
}

int DPS_PublicationIsAckRequested(const DPS_Publication* pub)
{
    return pub ? pub->ackRequested : 0;
}

/*
 * @param keyStore the key store used in decryption
 * @param pub the publication to decrypt
 * @param data pointer to decrypted data.  This is only valid during
 *             the lifetime of the plainTextBuf and the publication.
 * @param dataLen the length of the decrypted data.
 *
 * @return
 * - DPS_OK - message decrypted and parsed succesfully
 * - DPS_ERR_SECURITY - message failed to decrypt
 * - Other error - message failed to parse correctly
 */
static DPS_Status DecryptAndParsePub(DPS_KeyStore* keyStore, DPS_Publication* pub,
                                     DPS_RxBuffer* aadBuf, DPS_RxBuffer* cipherTextBuf,
                                     uint8_t** data, size_t* dataLen)
{
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_TOPICS, DPS_CBOR_KEY_DATA };
    uint8_t nonce[COSE_NONCE_LEN];
    COSE_Entity recipient;
    DPS_RxBuffer encryptedBuf;
    DPS_TxBuffer outBuf;
    DPS_RxBuffer buf;
    CBOR_MapState mapState;
    DPS_Status ret;
    size_t i;

    /*
     * Try to decrypt the publication
     */
    DPS_MakeNonce(&pub->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);

    ret = COSE_Decrypt(nonce, &recipient, aadBuf, cipherTextBuf, keyStore, &pub->sender, &outBuf);
    if (ret == DPS_OK) {
        DPS_DBGPRINT("Publication was decrypted\n");
        CBOR_Dump("plaintext", plainTextBuf->base, DPS_TxBufferUsed(plainTextBuf));
        DPS_TxBufferToRx(&outBuf, &buf);
        /*
         * We will use the same key id when we encrypt the acknowledgement
         */
        if (pub->ackRequested) {
            /*
             * Symmetric keys can use the recipient directly.
             * Asymmetric keys must use the sender info if provided.
             */
            switch (recipient.alg) {
            case COSE_ALG_DIRECT:
            case COSE_ALG_A256KW:
                if (AddRecipient(pub, recipient.alg, &recipient.kid)) {
                    ret = DPS_OK;
                } else {
                    ret = DPS_ERR_RESOURCES;
                }
                break;
            case COSE_ALG_ECDH_ES_A256KW:
                if (AddRecipient(pub, recipient.alg, &pub->sender.kid)) {
                    ret = DPS_OK;
                } else {
                    ret = DPS_ERR_RESOURCES;
                }
                break;
            default:
                ret = DPS_ERR_MISSING;
                break;
            }
            if (ret != DPS_OK) {
                DPS_WARNPRINT("Ack requested, but missing sender ID\n");
            }
        }
    } else if (ret == DPS_ERR_NOT_ENCRYPTED) {
        DPS_DBGPRINT("Publication was not encrypted\n");
        /*
         * The payload was not encrypted
         */
        buf = *cipherTextBuf;
    } else {
        DPS_WARNPRINT("Failed to decrypt publication - %s\n", DPS_ErrTxt(ret));
        return DPS_ERR_SECURITY;
    }
    ret = DPS_ParseMapInit(&mapState, &buf, EncryptedKeys, A_SIZEOF(EncryptedKeys), NULL, 0);
    if (ret != DPS_OK) {
        return ret;
    }
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            return ret;
        }
        switch (key) {
        case DPS_CBOR_KEY_TOPICS:
            /*
             * Deserialize the topic strings
             */
            ret = CBOR_DecodeArray(&buf, &pub->numTopics);
            if (ret != DPS_OK) {
                break;
            }
            if (pub->numTopics == 0) {
                ret = DPS_ERR_INVALID;
                break;
            }
            for (i = 0; i < pub->numTopics; ++i) {
                char* str;
                size_t sz;
                ret = CBOR_DecodeString(&buf, &str, &sz);
                if (ret != DPS_OK) {
                    break;
                }
                pub->topics[i] = str;
            }
            break;
        case DPS_CBOR_KEY_DATA:
            /*
             * Get the pointer to the publication data
             */
            ret = CBOR_DecodeBytes(&buf, data, dataLen);
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    return ret;
}

/*
 * Check if there is a local subscription for this publication
 * Note that we don't deliver expired publications to the handler.
 */
static DPS_Status CallPubHandlers(DPS_Publication* pub, DPS_TxBuffer* protectedBuf, DPS_TxBuffer* encryptedBuf)
{
    DPS_Status ret;
    DPS_Subscription* sub;
    DPS_Subscription* nextSub;
    DPS_TxBuffer plainTextBuf;
    int match;
    uint8_t* data = NULL;
    size_t dataLen = 0;
    int needsDecrypt = DPS_TRUE;

    DPS_DBGTRACE();

    DPS_TxBufferClear(&plainTextBuf);

    /*
     * Iterate over the candidates and check that the pub strings are a match
     */
    for (sub = node->subscriptions; sub != NULL; sub = nextSub) {
        nextSub = sub->next;
        if (!DPS_BitVectorIncludes(pub->bf, sub->bf)) {
            continue;
        }
        if (needsDecrypt) {
            ret = DecryptAndParsePub(node->keyStore, pub, protectedBuf, encryptedBuf, &data, &dataLen);
            if (ret == DPS_ERR_SECURITY) {
                /*
                 * This doesn't indicate an error with the message, it may be
                 * that the message is not encrypted for this node
                 */
                ret = DPS_OK;
                goto Exit;
            } else if (ret != DPS_OK) {
                goto Exit;
            }
            needsDecrypt = DPS_FALSE;
        }
        ret = DPS_MatchTopicList(pub->topics, pub->numTopics, sub->topics,
                                 sub->numTopics, node->separators, DPS_FALSE, &match);
        if (ret != DPS_OK) {
            ret = DPS_OK;
            continue;
        }
        if (match) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            sub->handler(sub, pub, data, dataLen);
        }
    }
    DPS_UnlockNode(node);

Exit:
    return ret;
}

static DPS_Publication* LookupRetained(DPS_Node* node, DPS_UUID* pubId)
{
    DPS_Publication* pub = NULL;

    DPS_LockNode(node);
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && (DPS_UUIDCompare(&pub->pubId, pubId) == 0)) {
            break;
        }
    }
    DPS_UnlockNode(node);
    return pub;
}

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buf, int multicast)
{
    static const int32_t UnprotectedKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_TTL };
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_TTL, DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_SEQ_NUM,
                                             DPS_CBOR_KEY_ACK_REQ, DPS_CBOR_KEY_BLOOM_FILTER };
    DPS_Status ret;
    uint16_t port;
    DPS_Publication pub = NULL;
    DPS_UUID* pubId = NULL;
    DPS_RxBuffer bfBuf;
    uint8_t* protectedPtr;
    CBOR_MapState mapState;
    uint32_t sequenceNum;
    int16_t ttl;
    int16_t baseTTL;
    int ackRequested;
    size_t len;

    DPS_DBGTRACE();

    CBOR_Dump("Pub in", buf->rxPos, DPS_RxBufferAvail(buf));
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
        case DPS_CBOR_KEY_TTL:
            ret = CBOR_DecodeInt16(buf, &ttl);
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
     * Start of publication protected map
     */
    protectedPtr = buf->rxPos;
    /*
     * Parse keys from protected map
     */
    ret = DPS_ParseMapInit(&mapState, buf, ProtectedKeys, A_SIZEOF(ProtectedKeys), NULL, 0);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Parse out the protected fields
     */
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_TTL:
            ret = CBOR_DecodeInt16(buf, &baseTTL);
            /*
             * Validate the current TTL against the base TTL
             */
            if (ret == DPS_OK) {
                if (((baseTTL < 0) && (ttl >= 0)) || (ttl > baseTTL)) {
                    DPS_ERRPRINT("TTL inconsistency - ttl=%d, baseTTL=%d\n", ttl, baseTTL);
                    ret = DPS_ERR_INVALID;
                }
            }
            break;
        case DPS_CBOR_KEY_PUB_ID:
            ret = CBOR_DecodeBytes(buf, (uint8_t**)&pubId, &len);
            if ((ret == DPS_OK) && (len != sizeof(DPS_UUID))) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(buf, &sequenceNum);
            if ((ret == DPS_OK) && (sequenceNum == 0)) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_ACK_REQ:
            ret = CBOR_DecodeBoolean(buf, &ackRequested);
            break;
        case DPS_CBOR_KEY_BLOOM_FILTER:
            /*
             * Skip the bloom filter for now
             */
            ret = CBOR_Skip(buf, NULL, &len);
            if (ret == DPS_OK) {
                DPS_RxBufferInit(&bfBuf, buf->rxPos - len, len);
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
     * Record which port the sender is listening on
     */
    //DPS_EndpointSetPort(ep, port);

    /*
     * A stale publication is a publication that has the same or older sequence number than the
     * latest publication with the same pubId.
     */
    if (DPS_PublicationIsStale(&node->history, pubId, sequenceNum)) {
        DPS_DBGPRINT("Publication %s/%d is stale\n", DPS_UUIDToString(pubId), sequenceNum);
        return DPS_ERR_STALE;
    }
    memcpy(&pub.pubId, pubId, sizeof(DPS_UUID));
    pub.sequenceNum = sequenceNum;
    pub.ackRequested = ackRequested;
    pub.senderAddr = ep->addr;
    /*
     * A negative TTL is a forced expiration. We don't care about payloads and
     * we don't call local handlers.
     */
    if (ttl < 0) {
        ttl = 0;
    } else {
        /*
         * Now we can deserialize the bloom filter
         */
        ret = DPS_BitVectorDeserialize(&pub.bf, &bfBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /*
         * Initialize the protected and encrypted buffers
         */
        ret = DPS_TxBufferInit(&protectedBuf, protectedPtr, buf->rxPos - protectedPtr);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = DPS_TxBufferInit(&encryptedBuf, buf->rxPos, DPS_RxBufferAvail(buf));
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = CallPubHandlers(pub, &protectedBuf, &encryptedBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    return DPS_OK;

Exit:
    return ret;
}

DPS_Status DPS_InitPublication(DPS_Node* node, DPS_Publication* pub, const char** topics, size_t numTopics, int noWildCard, const DPS_KeyId* keyId, DPS_AcknowledgementHandler handler)
{
    DPS_Status ret = DPS_OK;
    int8_t alg;

    DPS_DBGTRACE();

    /*
     * Must have at least one topic
     */
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    if (numTopics > MAX_PUB_TOPICS) {
        return DPS_ERR_RESOURCES;
    }
    DPS_GenerateUUID(&pub->pubId);

    DPS_DBGPRINT("Creating publication with %zu topics %s\n", numTopics, handler ? "and ACK handler" : "");

    pub->node = node;
    if (handler) {
        pub->handler = handler;
        pub->ackRequested = DPS_TRUE;
    }
    /*
     * Copy key identifier
     */
    if (keyId) {
        DPS_DBGPRINT("Publication has a keyId\n");
        ret = GetRecipientAlgorithm(node->keyStore, keyId, &alg);
        if (ret == DPS_OK) {
            if (!AddRecipient(pub, alg, keyId)) {
                ret = DPS_ERR_RESOURCES;
            }
        }
    }
    if (ret == DPS_OK) {
        size_t i;
        DPS_BitVectorClear(&pub->bf);
        for (i = 0; i < numTopics; ++i) {
            ret = DPS_AddTopic(pub->bf, topics[i], node->separators, noWildCard ? DPS_PubNoWild : DPS_PubTopic);
            if (ret != DPS_OK) {
                break;
            }
            pub->topics[i] = topics[i];
            ++pub->numTopics;
        }
    }
    return ret;
}

DPS_Status DPS_PublicationAddSubId(DPS_Publication* pub, const DPS_KeyId* keyId)
{
    DPS_Status ret;
    int8_t alg;

    DPS_DBGTRACE();

    DPS_DBGPRINT("Publication has a keyId\n");
    ret = GetRecipientAlgorithm(pub->node->keyStore, keyId, &alg);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!AddRecipient(pub, alg, keyId)) {
        return DPS_ERR_RESOURCES;
    }
    return DPS_OK;
}

void DPS_PublicationRemoveSubId(DPS_Publication* pub, const DPS_KeyId* keyId)
{
    DPS_DBGTRACE();
    RemoveRecipient(pub, keyId);
}

static size_t TopicsSerializedSize(DPS_Publication* pub)
{
    const char** topics = pub->topics;
    size_t i;
    size_t sz = CBOR_SIZE_OF_ARRAY(pub->numTopics);

    for (i = 0; i < pub->numTopics; ++i) {
        sz += CBOR_SIZEOF_STRING(pub->topics[i]);
    }
    return sz;
}

static DPS_Status SerializePub(DPS_Node* node, DPS_Publication* pub, const uint8_t* data, size_t dataLen, int16_t ttl)
{
    DPS_Status ret;
    size_t len;
    size_t bfLen = DPS_BitVectorSerializedSize(&pub->bfBuf);
    size_t topicsLen = TopicsSerializedSize(pub);
    DPS_TxBuffer buf;
    DPS_TxBuffer protectedBuf;
    DPS_TxBuffer encryptedBuf;

    DPS_DBGTRACE();

    /* Free the Tx buffer pools */
    DPS_TxBufferFreePool(node, DPS_TX_POOL);
    DPS_TxBufferFreePool(node, DPS_TMP_POOL);

    /*
     * Encode the unprotected map
     */
    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint16_t) +
        CBOR_SIZEOF(int16_t);

    ret = DPS_TxBufferAlloc(node, &buf, len, DPS_TX_POOL);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_PUB);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint16(&buf, node->port);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_TTL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&buf, ttl);
    }
    /*
     * Encode the protected map
     */
    len = CBOR_SIZEOF_MAP(5) + 5 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
        CBOR_SIZEOF(uint32_t) +
        CBOR_SIZEOF_BOOLEAN() +
        CBOR_SIZEOF_BYTES(bfLen) +
        CBOR_SIZEOF(int16_t);

    ret = DPS_TxBufferAlloc(node, &protectedBuf, len, DPS_Tx_POOL);
    if (ret != DPS_OK) {
        return DPS_ERR_RESOURCES;
    }
    ret = CBOR_EncodeMap(&protectedBuf, 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_TTL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&protectedBuf, ttl);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&protectedBuf, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&protectedBuf, pub->sequenceNum);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_ACK_REQ);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBoolean(&protectedBuf, pub->ackRequested);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_BLOOM_FILTER);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(&protectedBuf, pub->bfBuf.base, bfLen);
    }
    /*
     * Encode the encrypted map
     */
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) + topicsLen + CBOR_SIZEOF_BYTES(dataLen);
        ret = DPS_TxBufferAlloc(node, &encryptedBuf, len, DPS_TMP_POOL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&encryptedBuf, 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&encryptedBuf, DPS_CBOR_KEY_TOPICS);
    }
    /* Topic string array */
    if (ret == DPS_OK) {
        int i;
        ret = CBOR_EncodeArray(&encryptedBuf, pub->numTopics);
        for (i = 0; ret == DPS_OK && i < numTopics; ++i) {
            ret = CBOR_EncodeString(&encryptedBuf, pub->topic[i]);
        }
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&encryptedBuf, DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&encryptedBuf, data, dataLen);
    }
    if (ret != DPS_OK) {
        return ret;
    }

    if (pub->numRecipients > 0) {
        DPS_RxBuffer plainTextBuf;
        DPS_RxBuffer aadBuf;
        uint8_t nonce[COSE_NONCE_LEN];

        /* Encryption needs the input buffers to be Rx buffers */
        DPS_TxBufferToRx(&encryptedBuf, &plainTextBuf);
        DPS_TxBufferToRx(&protectedBuf, &aadBuf);
        DPS_MakeNonce(&pub->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);
        ret = COSE_Encrypt(node, COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                pub->recipients, pub->numRecipients, &aadBuf, &plainTextBuf,
                node->keyStore, &encryptedBuf);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
        DPS_DBGPRINT("Publication was encrypted\n");
        CBOR_Dump("aad", aadBuf.base, DPS_RxBufferAvail(&aadBuf));
        CBOR_Dump("cryptText", encryptedBuf.base, DPS_TxBufferUsed(&encryptedBuf));
    }
    return ret;
}

DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* payload, size_t len, int16_t ttl)
{
    DPS_Status ret;
    DPS_Publication* newClone = NULL;
    DPS_Publication* clone;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    ret = SerializePub(node, clone, payload, len, ttl);
    if (ret == DPS_OK) {
        ++pub->sequenceNum;
    }
    return ret;
}

DPS_Status DPS_SetPublicationData(DPS_Publication* pub, void* data)
{
    if (pub) {
        pub->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetPublicationData(const DPS_Publication* pub)
{
    return pub ?  pub->userData : NULL;
}

#if 0
DPS_Publication* DPS_LookupAckHandler(DPS_Node* node, const DPS_UUID* pubId, uint32_t sequenceNum)
{
    DPS_Publication* pub;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->handler && (DPS_UUIDCompare(&pub->pubId, pubId) == 0)) {
            if (pub->sequenceNum == sequenceNum) {
                return pub;
            }
        }
    }
    return NULL;
}
#endif
