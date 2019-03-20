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
#include "coap.h"
#include "compat.h"
#include "cose.h"
#include "history.h"
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "topics.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define RemoteNodeAddressText(n)  DPS_NodeAddrToString(&(n)->ep.addr)

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
        return DPS_ERR_MISSING;
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
    COSE_Entity* newRecipients;
    size_t newCap;
    DPS_KeyId newId;
    COSE_Entity* recipient;

    if (pub->recipientsCount == pub->recipientsCap) {
        newCap = 1;
        if (pub->recipientsCap) {
            newCap = pub->recipientsCap * 2;
        }
        newRecipients = realloc(pub->recipients, newCap * sizeof(COSE_Entity));
        if (!newRecipients) {
            return NULL;
        }
        pub->recipients = newRecipients;
        pub->recipientsCap = newCap;
    }
    if (!DPS_CopyKeyId(&newId, kid)) {
        return NULL;
    }

    recipient = &pub->recipients[pub->recipientsCount];
    recipient->alg = alg;
    recipient->kid = newId;
    ++pub->recipientsCount;
    return recipient;
}

static void RemoveRecipient(DPS_Publication* pub, const DPS_KeyId* kid)
{
    size_t i;

    for (i = 0; i < pub->recipientsCount; ++i) {
        if ((pub->recipients[i].kid.len == kid->len) &&
            (memcmp(pub->recipients[i].kid.id, kid->id, kid->len) == 0)) {
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

static void FreeRecipients(DPS_Publication* pub)
{
    size_t i;

    for (i = 0; i < pub->recipientsCount; ++i) {
        free((uint8_t*)pub->recipients[i].kid.id);
    }
    free(pub->recipients);
    pub->recipients = NULL;
    pub->recipientsCount = 0;
    pub->recipientsCap = 0;
}

static DPS_Status CopyRecipients(DPS_Publication* dst, const DPS_Publication* src)
{
    COSE_Entity* newRecipients = NULL;
    size_t newCount = 0;
    size_t i;

    if (src->recipients) {
        newRecipients = malloc(src->recipientsCap * sizeof(COSE_Entity));
        if (!newRecipients) {
            goto ErrorExit;
        }
        for (i = 0; i < src->recipientsCount; ++i) {
            newRecipients[i].alg = src->recipients[i].alg;
            if (!DPS_CopyKeyId(&newRecipients[i].kid, &src->recipients[i].kid)) {
                goto ErrorExit;
            }
            ++newCount;
        }
    }

    FreeRecipients(dst);
    dst->recipients = newRecipients;
    dst->recipientsCount = newCount;
    dst->recipientsCap = src->recipientsCap;
    return DPS_OK;

 ErrorExit:
    if (newRecipients) {
        for (i = 0; i < newCount; ++i) {
            DPS_ClearKeyId(&newRecipients[i].kid);
        }
        free(newRecipients);
    }
    return DPS_ERR_RESOURCES;
}

static void FreeTopics(DPS_Publication* pub)
{
    size_t i;

    assert(pub);
    assert(pub);

    if (pub->topics) {
        for (i = 0; i < pub->numTopics; ++i) {
            if (pub->topics[i]) {
                free(pub->topics[i]);
            }
        }
        free(pub->topics);
        pub->topics = NULL;
        pub->numTopics = 0;
    }
}

void DPS_DestroyPublishRequest(DPS_PublishRequest* req)
{
    if (req) {
        if (req->rxBuf) {
            /*
             * The request buffers are aliased to the received message buffer.
             */
            DPS_NetRxBufferDecRef(req->rxBuf);
        } else {
            /*
             * The request buffers are not aliased.
             */
            DPS_TxBufferFree(&req->bufs[0]);
            DPS_TxBufferFree(&req->bufs[1]);
            DPS_TxBufferFree(&req->bufs[2]);
            /*
             * Request buffers [3, req->numBufs - 1) belong to the application
             */
            DPS_TxBufferFree(&req->bufs[req->numBufs - 1]);
        }
        free(req);
    }
}

static DPS_Publication* FreePublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Publication* next = pub->next;
    DPS_PublishRequest* req;

    if (!(pub->flags & PUB_FLAG_WAS_FREED)) {
        if (node->publications == pub) {
            node->publications = next;
        } else {
            DPS_Publication* prev = node->publications;
            while (prev && (prev->next != pub)) {
                prev = prev->next;
            }
            if (prev) {
                prev->next = next;
            }
        }
        pub->next = NULL;
        pub->flags = PUB_FLAG_WAS_FREED;
    }
    /*
     * If the ref count is non zero the publication buffers are being referenced
     * by the network layer code so cannot be free yet. FreePublication will be
     * called from OnNetSendComplete() or OnMulticastSendComplete() when the ref
     * count goes to zero.
     */
    if (pub->refCount == 0) {
        while (!DPS_QueueEmpty(&pub->sendQueue)) {
            req = (DPS_PublishRequest*)DPS_QueueFront(&pub->sendQueue);
            DPS_QueueRemove(&req->queue);
            assert(req->refCount > 0);
            --req->refCount;
            req->status = DPS_ERR_WRITE;
            DPS_PublishCompletion(req);
        }
        while (!DPS_QueueEmpty(&pub->retainedQueue)) {
            req = (DPS_PublishRequest*)DPS_QueueFront(&pub->retainedQueue);
            DPS_QueueRemove(&req->queue);
            assert(req->refCount > 0);
            --req->refCount;
            req->status = DPS_ERR_WRITE;
            DPS_PublishCompletion(req);
        }
        FreeRecipients(pub);
        if (pub->bf) {
            DPS_BitVectorFree(pub->bf);
        }
        DPS_TxBufferFree(&pub->bfBuf);
        DPS_TxBufferFree(&pub->topicsBuf);
        FreeTopics(pub);
        free(pub);
    }
    return next;
}

void DPS_PublicationIncRef(DPS_Publication* pub)
{
    ++pub->refCount;
}

void DPS_PublicationDecRef(DPS_Publication* pub)
{
    assert(pub->refCount != 0);
    if ((--pub->refCount == 0) && (pub->flags & PUB_FLAG_WAS_FREED)) {
        FreePublication(pub->node, pub);
    }
}

void DPS_FreePublications(DPS_Node* node)
{
    while (node->publications) {
        node->publications = FreePublication(node, node->publications);
    }
}

static int IsValidPub(const DPS_Publication* pub)
{
    DPS_Node* node;
    DPS_Publication* pubList;

    if (!pub|| !pub->node || !pub->node->loop) {
        return DPS_FALSE;
    }
    node = pub->node;
    DPS_LockNode(node);
    for (pubList = node->publications; pubList; pubList = pubList->next) {
        if (pub == pubList) {
            break;
        }
    }
    DPS_UnlockNode(node);
    return pubList != NULL;
}

const DPS_UUID* DPS_PublicationGetUUID(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return &pub->pubId;
    } else {
        return NULL;
    }
}

uint32_t DPS_PublicationGetSequenceNum(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->sequenceNum;
    } else {
        return 0;
    }
}

size_t DPS_PublicationGetNumTopics(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->numTopics;
    } else {
        return 0;
    }
}

const char* DPS_PublicationGetTopic(const DPS_Publication* pub, size_t index)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) && (pub->numTopics > index)) {
        return pub->topics[index];
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_PublicationGetSenderKeyId(const DPS_Publication* pub)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) &&
        (pub->sender.alg != COSE_ALG_RESERVED)) {
        return &pub->sender.kid;
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_AckGetSenderKeyId(const DPS_Publication* pub)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) &&
        (pub->ack.alg != COSE_ALG_RESERVED)) {
        return &pub->ack.kid;
    } else {
        return NULL;
    }
}

int DPS_PublicationIsAckRequested(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->ackRequested;
    } else {
        return 0;
    }
}

DPS_Node* DPS_PublicationGetNode(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->node;
    } else {
        return NULL;
    }
}

static DPS_Status UpdatePubHistory(DPS_PublishRequest* req)
{
    DPS_Publication* pub = req->pub;
    DPS_Node* node = pub->node;
    return DPS_UpdatePubHistory(&node->history, &pub->pubId, req->sequenceNum, pub->ackRequested,
                                REQ_TTL(req), &pub->senderAddr);
}

/*
 * @param pub the request to decrypt
 * @param plainTextBuf the storage for decrypted.  The caller needs to
 *                     call DPS_TxBufferFree when finished with the
 *                     decrypted data.
 * @param data pointer to decrypted data.  This is only valid during
 *             the lifetime of the plainTextBuf and the publication.
 * @param dataLen the length of the decrypted data.
 *
 * @return
 * - DPS_OK - message decrypted and parsed succesfully
 * - DPS_ERR_SECURITY - message failed to decrypt
 * - Other error - message failed to parse correctly
 */
static DPS_Status DecryptAndParsePub(DPS_PublishRequest* req, DPS_TxBuffer* plainTextBuf, uint8_t** data,
                                     size_t* dataLen)
{
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_TOPICS, DPS_CBOR_KEY_DATA };
    DPS_Publication* pub = req->pub;
    DPS_KeyStore* keyStore = pub->node->keyStore;
    uint8_t nonce[COSE_NONCE_LEN];
    DPS_RxBuffer aadBuf;
    DPS_RxBuffer cipherTextBuf;
    COSE_Entity recipient;
    DPS_RxBuffer encryptedBuf;
    CBOR_MapState mapState;
    uint8_t type;
    uint64_t tag;
    DPS_Status ret;
    size_t i;

    /*
     * Try to decrypt the publication
     */
    DPS_MakeNonce(&pub->pubId, req->sequenceNum, DPS_MSG_TYPE_PUB, nonce);
    DPS_TxBufferToRx(&req->bufs[0], &aadBuf);
    DPS_TxBufferToRx(&req->bufs[1], &cipherTextBuf);
    DPS_TxBufferClear(plainTextBuf);
    ret = CBOR_Peek(&cipherTextBuf, &type, &tag);
    if (ret == DPS_OK) {
        if (type == CBOR_TAG) {
            if ((tag == COSE_TAG_ENCRYPT0) || (tag == COSE_TAG_ENCRYPT)) {
                ret = COSE_Decrypt(nonce, &recipient, &aadBuf, &cipherTextBuf, keyStore, &pub->sender,
                                   plainTextBuf);
                if (ret == DPS_OK) {
                    DPS_DBGPRINT("Publication was decrypted\n");
                    CBOR_Dump("plaintext", plainTextBuf->base, DPS_TxBufferUsed(plainTextBuf));
                    DPS_TxBufferToRx(plainTextBuf, &encryptedBuf);
                    /*
                     * We will use the same key id when we encrypt the acknowledgement
                     */
                    if (pub->ackRequested) {
                        /*
                         * Symmetric keys can use the recipient directly.
                         * Asymmetric keys must use the sender info if provided.
                         */
                        switch (recipient.alg) {
                        case COSE_ALG_RESERVED:
                            /*
                             * Recipient is implicit or not present.
                             */
                            ret = DPS_OK;
                            break;
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
                }
            } else if (tag == COSE_TAG_SIGN1) {
                ret = COSE_Verify(&aadBuf, &cipherTextBuf, keyStore, &pub->sender);
                if (ret == DPS_OK) {
                    DPS_DBGPRINT("Publication was verified\n");
                    encryptedBuf = cipherTextBuf;
                    pub->rxBuf = req->rxBuf;
                }
            } else {
                ret = DPS_ERR_INVALID;
            }
        } else {
            DPS_DBGPRINT("Publication was not a COSE object\n");
            /*
             * The payload was not encrypted
             */
            DPS_TxBufferToRx(&req->bufs[1], &encryptedBuf);
            pub->rxBuf = req->rxBuf;
            ret = DPS_OK;
        }
    }
    if (ret != DPS_OK) {
        DPS_WARNPRINT("Failed to deserialize publication - %s\n", DPS_ErrTxt(DPS_ERR_SECURITY));
        return DPS_ERR_SECURITY;
    }
    ret = DPS_ParseMapInit(&mapState, &encryptedBuf, EncryptedKeys, A_SIZEOF(EncryptedKeys), NULL, 0);
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
            ret = CBOR_DecodeArray(&encryptedBuf, &pub->numTopics);
            if (ret != DPS_OK) {
                break;
            }
            if (pub->numTopics == 0) {
                ret = DPS_ERR_INVALID;
                break;
            }
            pub->topics = calloc(pub->numTopics, sizeof(char*));
            if (!pub->topics) {
                ret = DPS_ERR_RESOURCES;
                break;
            }
            for (i = 0; i < pub->numTopics; ++i) {
                char* str;
                size_t sz;
                ret = CBOR_DecodeString(&encryptedBuf, &str, &sz);
                if (ret != DPS_OK) {
                    break;
                }
                pub->topics[i] = strndup(str, sz);
                if (!pub->topics) {
                    ret = DPS_ERR_RESOURCES;
                    break;
                }
            }
            break;
        case DPS_CBOR_KEY_DATA:
            /*
             * Get the pointer to the publication data
             */
            ret = CBOR_DecodeBytes(&encryptedBuf, data, dataLen);
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
static DPS_Status CallPubHandlers(DPS_PublishRequest* req)
{
    DPS_Publication* pub = req->pub;
    DPS_Node* node = pub->node;
    DPS_Status ret = DPS_OK;
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
        DPS_SubscriptionIncRef(sub);
        if (!DPS_BitVectorIncludes(pub->bf, sub->bf)) {
            goto Next;
        }
        if (needsDecrypt) {
            DPS_UnlockNode(node);
            ret = DecryptAndParsePub(req, &plainTextBuf, &data, &dataLen);
            DPS_LockNode(node);
            if (ret == DPS_OK) {
                needsDecrypt = DPS_FALSE;
            } else {
                if (ret == DPS_ERR_SECURITY) {
                    /*
                     * This doesn't indicate an error with the message, it may be
                     * that the message is not encrypted for this node
                     */
                    ret = DPS_OK;
                }
                DPS_SubscriptionDecRef(sub);
                break;
            }
        }
        ret = DPS_MatchTopicList(pub->topics, pub->numTopics, sub->topics,
                                 sub->numTopics, node->separators, DPS_FALSE, &match);
        if (ret != DPS_OK) {
            ret = DPS_OK;
            goto Next;
        }
        if (match) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(req);
            DPS_UnlockNode(node);
            sub->handler(sub, pub, data, dataLen);
            DPS_LockNode(node);
        }
    Next:
        DPS_SubscriptionDecRef(sub);
    }
    pub->rxBuf = NULL;
    DPS_TxBufferFree(&plainTextBuf);
    /* Publication topics will be invalid now if the publication was encrypted */
    FreeTopics(pub);
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

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_NetRxBuffer* buf, int multicast)
{
    static const int32_t UnprotectedKeys[] = { DPS_CBOR_KEY_TTL };
    static const int32_t UnprotectedOptKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_PATH };
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_TTL, DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_SEQ_NUM,
                                             DPS_CBOR_KEY_ACK_REQ, DPS_CBOR_KEY_BLOOM_FILTER };
    DPS_RxBuffer* rxBuf = (DPS_RxBuffer*)buf;
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port = 0;
    DPS_Publication* pub = NULL;
    DPS_PublishRequest* req = NULL;
    uint8_t* bytes = NULL;
    DPS_UUID pubId;
    DPS_RxBuffer bfBuf;
    uint8_t* protectedPtr;
    CBOR_MapState mapState;
    uint32_t sequenceNum;
    int16_t ttl;
    int16_t baseTTL;
    int ackRequested;
    size_t len;
    char* path = NULL;
    size_t pathLen;
    uint16_t keysMask;

    DPS_DBGTRACE();

    CBOR_Dump("Pub in", rxBuf->rxPos, DPS_RxBufferAvail(rxBuf));
    /*
     * Parse keys from unprotected map
     */
    ret = DPS_ParseMapInit(&mapState, rxBuf, UnprotectedKeys, A_SIZEOF(UnprotectedKeys),
                           UnprotectedOptKeys, A_SIZEOF(UnprotectedOptKeys));
    if (ret != DPS_OK) {
        return ret;
    }
    keysMask = 0;
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PORT:
            keysMask |= (1 << key);
            ret = CBOR_DecodeUint16(rxBuf, &port);
            break;
        case DPS_CBOR_KEY_TTL:
            ret = CBOR_DecodeInt16(rxBuf, &ttl);
            break;
        case DPS_CBOR_KEY_PATH:
            keysMask |= (1 << key);
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
    if (ret != DPS_OK) {
        return ret;
    }
    if ((keysMask & ((1 << DPS_CBOR_KEY_PORT) | (1 << DPS_CBOR_KEY_PATH))) == 0) {
        DPS_WARNPRINT("Missing required key\n");
        return DPS_ERR_INVALID;
    }
    /*
     * Start of publication protected map
     */
    protectedPtr = rxBuf->rxPos;
    /*
     * Parse keys from protected map
     */
    ret = DPS_ParseMapInit(&mapState, rxBuf, ProtectedKeys, A_SIZEOF(ProtectedKeys), NULL, 0);
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
            ret = CBOR_DecodeInt16(rxBuf, &baseTTL);
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
            ret = CBOR_DecodeBytes(rxBuf, &bytes, &len);
            if ((ret == DPS_OK) && (len != sizeof(DPS_UUID))) {
                ret = DPS_ERR_INVALID;
            }
            if (ret == DPS_OK) {
                memcpy(&pubId.val, bytes, sizeof(DPS_UUID));
            }
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(rxBuf, &sequenceNum);
            if ((ret == DPS_OK) && (sequenceNum == 0)) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_ACK_REQ:
            ret = CBOR_DecodeBoolean(rxBuf, &ackRequested);
            break;
        case DPS_CBOR_KEY_BLOOM_FILTER:
            /*
             * Skip the bloom filter for now
             */
            ret = CBOR_Skip(rxBuf, NULL, &len);
            if (ret == DPS_OK) {
                DPS_RxBufferInit(&bfBuf, rxBuf->rxPos - len, len);
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
    if (keysMask & (1 << DPS_CBOR_KEY_PORT)) {
        DPS_EndpointSetPort(ep, port);
    } else {
        assert(keysMask & (1 << DPS_CBOR_KEY_PATH));
        DPS_EndpointSetPath(ep, path, pathLen);
    }

    DPS_LockNode(node);
    /*
     * Lookup an existing retained publication or create a new one.
     *
     * Add a reference so that publication remains alive while we use
     * it: the node lock will get released when we issue callbacks
     * into the application for crypto or subscription handlers below.
     */
    pub = LookupRetained(node, &pubId);
    if (pub) {
        /*
         * Retained publications can only be updated with newer revisions
         */
        if (sequenceNum <= pub->sequenceNum) {
            DPS_DBGPRINT("Publication %s/%d is stale (/%d already retained)\n", DPS_UUIDToString(&pubId),
                         sequenceNum, pub->sequenceNum);
            ret = DPS_ERR_STALE;
            /*
             * Set pub to NULL here so we don't delete it during
             * cleanup - we want to drop the stale revision, not
             * remove the most recent revision.
             */
            pub = NULL;
            goto Exit;
        }
        DPS_PublicationIncRef(pub);
    } else {
        /*
         * A stale publication is a publication that has the same or older sequence number than the
         * latest publication with the same pubId.
         */
        if (DPS_PublicationIsStale(&node->history, &pubId, sequenceNum)) {
            DPS_DBGPRINT("Publication %s/%d is stale\n", DPS_UUIDToString(&pubId), sequenceNum);
            ret = DPS_ERR_STALE;
            goto Exit;
        }
        pub = calloc(1, sizeof(DPS_Publication));
        if (!pub) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        pub->node = node;
        DPS_QueueInit(&pub->sendQueue);
        DPS_QueueInit(&pub->retainedQueue);
        DPS_PublicationIncRef(pub);
        pub->bf = DPS_BitVectorAlloc();
        if (!pub->bf) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        memcpy_s(&pub->pubId, sizeof(pub->pubId), &pubId, sizeof(DPS_UUID));
        /*
         * Link in the pub
         */
        pub->next = node->publications;
        node->publications = pub;
    }
    pub->sequenceNum = sequenceNum;
    pub->ackRequested = ackRequested;
    pub->senderAddr = ep->addr;
    /*
     * The topics array has pointers into pub->encryptedBuf which are now invalid
     */
    FreeTopics(pub);
    /*
     * We have no reason here to hold onto a node for multicast publishers
     */
    if (!multicast) {
        ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    /*
     * Allocate the publish request for handling and forwarding
     *
     * The DPS_ERR_NO_ROUTE status will be reported in the completion
     * callback if we do not forward the publication
     */
    req = DPS_CreatePublishRequest(pub, 0, NULL, NULL);
    if (!req) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    req->status = DPS_ERR_NO_ROUTE;
    req->sequenceNum = sequenceNum;
    req->rxBuf = buf;
    DPS_NetRxBufferIncRef(buf);
    DPS_TxBufferInit(&req->bufs[0], protectedPtr, rxBuf->rxPos - protectedPtr);
    req->bufs[0].txPos = req->bufs[0].eob;
    DPS_TxBufferInit(&req->bufs[1], rxBuf->rxPos, DPS_RxBufferAvail(rxBuf));
    req->bufs[1].txPos = req->bufs[1].eob;
    /*
     * A negative TTL is a forced expiration. We don't call local handlers.
     */
    if (ttl < 0) {
        /*
         * We only expect negative TTL's for retained publications
         */
        if (!(pub->flags & PUB_FLAG_RETAINED)) {
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        pub->flags |= PUB_FLAG_EXPIRED;
        ttl = 0;
    } else {
        /*
         * Now we can deserialize the bloom filter
         */
        ret = DPS_BitVectorDeserialize(pub->bf, &bfBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
        if (ttl > 0) {
            pub->flags |= PUB_FLAG_RETAINED;
        } else {
            pub->flags &= ~PUB_FLAG_RETAINED;
        }
        ret = CallPubHandlers(req);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    req->ttl = ttl;
    req->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    UpdatePubHistory(req);
    DPS_QueuePushBack(&pub->sendQueue, &req->queue);
    ++req->refCount;
    uv_async_send(&node->pubsAsync);
    ret = DPS_OK;

Exit:
    if (req && (ret != DPS_OK)) {
        assert(pub);
        req->status = ret;
        DPS_DestroyPublishRequest(req);
    }
    /*
     * Delete the publisher node if it is sending bad data
     */
    if (ret == DPS_ERR_INVALID || ret == DPS_ERR_SECURITY) {
        DPS_ERRPRINT("Deleting bad publisher\n");
        DPS_DeleteRemoteNode(node, pubNode);
    }
    if (pub) {
        if (ret != DPS_OK) {
            /*
             * TODO - should we be updating the pub history after an error?
             */
            DPS_UpdatePubHistory(&node->history, &pub->pubId, sequenceNum, pub->ackRequested, ttl,
                                 &pub->senderAddr);
            FreePublication(node, pub);
        }
        DPS_PublicationDecRef(pub);
    }
    DPS_UnlockNode(node);
    return ret;
}

static void SendComplete(DPS_PublishRequest* req, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs,
                         DPS_Status status)
{
    DPS_Publication* pub = req->pub;
    DPS_Node* node = pub->node;

    assert(req->refCount > 0);
    --req->refCount;
    /*
     * If at least one send succeeds, report success to the requester
     */
    if (req->status != DPS_OK) {
        req->status = status;
    }
    /*
     * Only the first buffer belongs to us
     */
    if (numBufs > 0) {
        numBufs = 1;
    }
    DPS_SendComplete(node, ep ? &ep->addr : NULL, bufs, numBufs, status);
}

static void OnNetSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs,
                              size_t numBufs, DPS_Status status)
{
    DPS_PublishRequest* req = appCtx;
    DPS_Publication* pub = req->pub;

    DPS_LockNode(node);
    SendComplete(req, ep, bufs, numBufs, status);
    DPS_PublishCompletion(req);
    DPS_PublicationDecRef(pub);
    DPS_UnlockNode(node);
}

static void OnMulticastSendComplete(DPS_MulticastSender* sender, void* appCtx, uv_buf_t* bufs,
                                    size_t numBufs, DPS_Status status)
{
    DPS_PublishRequest* req = appCtx;
    DPS_Publication* pub = req->pub;
    DPS_Node* node = pub->node;

    DPS_LockNode(node);
    SendComplete(req, NULL, bufs, numBufs, status);
    DPS_PublishCompletion(req);
    DPS_PublicationDecRef(pub);
    DPS_UnlockNode(node);
}

DPS_Status DPS_SendPublication(DPS_PublishRequest* req, DPS_Publication* pub, RemoteNode* remote)
{
    DPS_Node* node = pub->node;
    DPS_Status ret;
    DPS_TxBuffer buf;
    size_t len;
    int16_t ttl = 0;
    size_t i;

    DPS_DBGTRACE();

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    if (pub->flags & PUB_FLAG_RETAINED) {
        if (pub->flags & PUB_FLAG_EXPIRED) {
            ttl = -1;
        } else {
            ttl = REQ_TTL(req);
            /*
             * It is possible that a retained publication has expired between
             * being marked to send and getting to this point; if so we
             * silently ignore the publication.
             */
            if (ttl <= 0) {
                ++req->refCount;
                SendComplete(req, NULL, NULL, 0, DPS_OK);
                return DPS_OK;
            }
        }
    }

    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(int16_t);   /* ttl */
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
    ret = DPS_TxBufferInit(&buf, NULL, len);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_VERSION);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_MSG_TYPE_PUB);
    }
    /*
     * Encode the unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&buf, 2);
    }
    switch (node->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_PORT);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint16(&buf,
                                    DPS_NetAddrPort((const struct sockaddr*)&node->addr.u.inaddr));
        }
        break;
    default:
        break;
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&buf, DPS_CBOR_KEY_TTL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&buf, ttl);
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
     * Protected and encrypted maps are already serialized
     */
    if (ret == DPS_OK) {
        uv_buf_t bufs[1 + NUM_INTERNAL_PUB_BUFS + DPS_BUFS_MAX];
        bufs[0] = uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf));
        for (i = 0; i < req->numBufs; ++i) {
            bufs[1 + i] = uv_buf_init((char*)req->bufs[i].base, DPS_TxBufferUsed(&req->bufs[i]));
        }
        ++req->refCount;
        if (remote == DPS_LoopbackNode) {
            ret = DPS_LoopbackSend(node, bufs, 1 + req->numBufs);
            SendComplete(req, NULL, bufs, 1 + req->numBufs, ret);
        } else if (remote) {
            ret = DPS_NetSend(node, req, &remote->ep, bufs, 1 + req->numBufs, OnNetSendComplete);
            if (ret == DPS_OK) {
                /*
                 * Prevent the publication from being freed until the send completes.
                 */
                DPS_PublicationIncRef(pub);
                /*
                 * Update history to prevent retained publications from being resent.
                 */
                DPS_UpdatePubHistory(&node->history, &pub->pubId, req->sequenceNum,
                                     pub->ackRequested, REQ_TTL(req), &remote->ep.addr);
            } else {
                SendComplete(req, &remote->ep, bufs, 1 + req->numBufs, ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, req, bufs, 1 + req->numBufs, OnMulticastSendComplete);
            if (ret == DPS_OK) {
                DPS_PublicationIncRef(pub);
            } else {
                DPS_WARNPRINT("DPS_MulticastSend failed - %s\n", DPS_ErrTxt(ret));
                if (ret == DPS_ERR_NO_ROUTE) {
                    /*
                     * Rewrite the error to make DPS_SendPublication a no-op when
                     * there are no multicast interfaces available.
                     */
                    ret = DPS_OK;
                }
                SendComplete(req, NULL, bufs, 1 + req->numBufs, ret);
            }
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

DPS_PublishRequest* DPS_CreatePublishRequest(DPS_Publication* pub, size_t numBufs, DPS_PublishBufsComplete cb,
                                             void* data)
{
    DPS_PublishRequest* req = NULL;

    /*
     * Reserve additional buffers for the authenticated fields,
     * optional COSE headers, payload headers, and optional COSE
     * footers.
     */
    numBufs += NUM_INTERNAL_PUB_BUFS;
    req = calloc(1, sizeof(DPS_PublishRequest) + ((numBufs - 1) * sizeof(DPS_TxBuffer)));
    if (!req) {
        return NULL;
    }
    req->pub = pub;
    req->completeCB = cb;
    req->data = data;
    req->status = DPS_ERR_FAILURE;
    req->rxBuf = NULL;
    req->numBufs = numBufs;
    return req;
}

void DPS_PublishCompletion(DPS_PublishRequest* req)
{
    DPS_Buffer bufs[DPS_BUFS_MAX];
    size_t numBufs = 0;
    size_t i;

    if (req->refCount == 0) {
        if (req->completeCB) {
            if (req->numBufs > NUM_INTERNAL_PUB_BUFS) {
                numBufs = req->numBufs - NUM_INTERNAL_PUB_BUFS;
                for (i = 0; i < numBufs; ++i) {
                    bufs[i].base = req->bufs[i + 3].base;
                    bufs[i].len = DPS_TxBufferUsed(&req->bufs[i + 3]);
                }
            }
            req->completeCB(req->pub, numBufs ? bufs : NULL, numBufs, req->status, req->data);
        }
        DPS_DestroyPublishRequest(req);
    }
}

void DPS_ExpirePub(DPS_Node* node, DPS_Publication* pub)
{
    if (pub->flags & PUB_FLAG_LOCAL) {
        pub->flags |= PUB_FLAG_EXPIRED;
    } else {
        DPS_DBGPRINT("Expiring %spub %s\n", pub->flags & PUB_FLAG_RETAINED ? "retained " : "",
                     DPS_UUIDToString(&pub->pubId));
        FreePublication(node, pub);
    }
}

DPS_Publication* DPS_CreatePublication(DPS_Node* node)
{
    DPS_Publication* pub;

    DPS_DBGTRACE();

    if (!node) {
        return NULL;
    }
    /*
     * Create the publication
     */
    pub = calloc(1, sizeof(DPS_Publication));
    if (!pub) {
        return NULL;
    }
    DPS_GenerateUUID(&pub->pubId);
    pub->node = node;
    DPS_QueueInit(&pub->sendQueue);
    DPS_QueueInit(&pub->retainedQueue);
    return pub;
}

static void DestroyCopy(DPS_Publication* copy)
{
    if (copy && copy->refCount == 0) {
        FreeTopics(copy);
        FreeRecipients(copy);
        free(copy);
    }
}

DPS_Publication* DPS_CopyPublication(const DPS_Publication* pub)
{
    DPS_Publication* copy;
    DPS_Status ret = DPS_ERR_RESOURCES;

    DPS_DBGTRACE();

    if (!pub->node) {
        return NULL;
    }
    copy = calloc(1, sizeof(DPS_Publication));
    if (!copy) {
        DPS_ERRPRINT("malloc failure: no memory\n");
        goto Exit;
    }
    copy->flags = PUB_FLAG_IS_COPY;
    copy->sequenceNum = pub->sequenceNum;
    copy->ackRequested = pub->ackRequested;
    copy->handler = pub->handler;
    copy->pubId = pub->pubId;
    copy->sender = pub->sender;
    if (pub->ackRequested) {
        ret = CopyRecipients(copy, pub);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CopyRecipients failed: %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
    }
    copy->node = pub->node;
    copy->numTopics = pub->numTopics;
    if (pub->numTopics > 0) {
        size_t i;
        copy->topics = calloc(pub->numTopics, sizeof(char*));
        if (!copy->topics) {
            DPS_ERRPRINT("malloc failure: no memory\n");
            goto Exit;
        }
        for (i = 0; i < pub->numTopics; i++) {
            copy->topics[i] = strndup(pub->topics[i], DPS_MAX_TOPIC_STRLEN);
        }
    }
    ret = DPS_OK;

Exit:
    if (ret != DPS_OK) {
        DestroyCopy(copy);
        copy = NULL;
    }
    return copy;
}

DPS_Status DPS_InitPublication(DPS_Publication* pub,
                               const char** topics,
                               size_t numTopics,
                               int noWildCard,
                               const DPS_KeyId* keyId,
                               DPS_AcknowledgementHandler handler)
{
    DPS_Node* node = pub ? pub->node : NULL;
    DPS_Status ret = DPS_OK;
    int8_t alg;
    size_t i;

    DPS_DBGTRACE();

    if (!node) {
        return DPS_ERR_NULL;
    }
    if (!node->loop) {
        return DPS_ERR_NOT_STARTED;
    }
    /*
     * Check publication can be initialized
     */
    if ((pub->flags & PUB_FLAG_IS_COPY) || pub->bf || pub->topics) {
        return DPS_ERR_INVALID;
    }
    /*
     * Must have at least one topic
     */
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    DPS_DBGPRINT("Creating publication with %zu topics %s\n", numTopics, handler ? "and ACK handler" : "");
    if (DPS_DEBUG_ENABLED()) {
        DPS_DumpTopics(topics, numTopics);
    }

    pub->bf = DPS_BitVectorAlloc();
    if (!pub->bf) {
        return DPS_ERR_RESOURCES;
    }
    if (handler) {
        pub->handler = handler;
        pub->ackRequested = DPS_TRUE;
    }
    pub->flags = PUB_FLAG_LOCAL;
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
        for (i = 0; i < numTopics; ++i) {
            ret = DPS_AddTopic(pub->bf, topics[i], node->separators,
                               noWildCard ? DPS_PubNoWild : DPS_PubTopic);
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    if (ret == DPS_OK) {
        pub->topics = calloc(numTopics, sizeof(char*));
        if (!pub->topics) {
            ret = DPS_ERR_RESOURCES;
        }
        pub->numTopics = numTopics;
    }
    /*
     * Serialize the topics
     */
    if (ret == DPS_OK) {
        size_t bufLen = CBOR_SIZEOF_ARRAY(numTopics);
        for (i = 0; i < numTopics; ++i) {
            bufLen += CBOR_SIZEOF_STRING(topics[i]);
        }
        assert(!pub->topicsBuf.base);
        ret = DPS_TxBufferInit(&pub->topicsBuf, NULL, bufLen);
        if (ret == DPS_OK) {
            ret = CBOR_EncodeArray(&pub->topicsBuf, numTopics);
        }
        if (ret == DPS_OK) {
            for (i = 0; i < numTopics; ++i) {
                ret = CBOR_EncodeString(&pub->topicsBuf, topics[i]);
                if (ret != DPS_OK) {
                    break;
                }
                pub->topics[i] = strndup(topics[i], DPS_MAX_TOPIC_STRLEN);
                if (!pub->topics[i]) {
                    ret = DPS_ERR_RESOURCES;
                    break;
                }
            }
        }
    }
    /*
     * Serialize the bloom filter
     */
    if (ret == DPS_OK) {
        ret = DPS_TxBufferInit(&pub->bfBuf, NULL, 32 + DPS_BitVectorSerializeMaxSize(pub->bf));
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(pub->bf, &pub->bfBuf);
        }
    }

    if (ret == DPS_OK) {
        DPS_LockNode(node);
        pub->next = node->publications;
        node->publications = pub;
        DPS_UnlockNode(node);
    } else {
        DPS_TxBufferFree(&pub->bfBuf);
        DPS_TxBufferFree(&pub->topicsBuf);
        FreeTopics(pub);
        FreeRecipients(pub);
        if (pub->bf) {
            DPS_BitVectorFree(pub->bf);
            pub->bf = NULL;
        }
    }
    return ret;
}

DPS_Status DPS_PublicationAddSubId(DPS_Publication* pub, const DPS_KeyId* keyId)
{
    DPS_Status ret;
    int8_t alg;

    DPS_DBGTRACE();

    if (IsValidPub(pub)) {
        DPS_DBGPRINT("Publication has a keyId\n");
        ret = GetRecipientAlgorithm(pub->node->keyStore, keyId, &alg);
        if (ret != DPS_OK) {
            return ret;
        }
        if (!AddRecipient(pub, alg, keyId)) {
            return DPS_ERR_RESOURCES;
        }
        return DPS_OK;
    } else {
        return DPS_ERR_ARGS;
    }
}

void DPS_PublicationRemoveSubId(DPS_Publication* pub, const DPS_KeyId* keyId)
{
    DPS_DBGTRACE();

    if (IsValidPub(pub)) {
        RemoveRecipient(pub, keyId);
    }
}

int DPS_PublicationIsEncrypted(const DPS_Publication* pub)
{
    return pub && pub->recipients;
}

DPS_Status DPS_SerializePub(DPS_PublishRequest* req, const DPS_Buffer* bufs, size_t numBufs, int16_t ttl)
{
    DPS_Publication* pub = req->pub;
    DPS_Node* node = pub->node;
    size_t bfLen = DPS_TxBufferUsed(&pub->bfBuf);
    size_t topicsLen = DPS_TxBufferUsed(&pub->topicsBuf);
    size_t dataLen;
    DPS_Status ret;
    size_t len;
    size_t i;

    assert(req->numBufs == numBufs + NUM_INTERNAL_PUB_BUFS);

    /*
     * Encode the protected map
     */
    len = CBOR_SIZEOF_MAP(5) + 5 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
        CBOR_SIZEOF(uint32_t) +
        CBOR_SIZEOF_BOOLEAN() +
        CBOR_SIZEOF_BYTES(bfLen) +
        CBOR_SIZEOF(int16_t);
    ret = DPS_TxBufferInit(&req->bufs[0], NULL, len);
    if (ret != DPS_OK) {
        return DPS_ERR_RESOURCES;
    }
    ret = CBOR_EncodeMap(&req->bufs[0], 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[0], DPS_CBOR_KEY_TTL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&req->bufs[0], ttl);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[0], DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&req->bufs[0], (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[0], DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&req->bufs[0], req->sequenceNum);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[0], DPS_CBOR_KEY_ACK_REQ);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBoolean(&req->bufs[0], pub->ackRequested);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[0], DPS_CBOR_KEY_BLOOM_FILTER);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(&req->bufs[0], pub->bfBuf.base, bfLen);
    }
    /*
     * Encode the encrypted map
     */
    DPS_TxBufferClear(&req->bufs[1]);
    dataLen = 0;
    for (i = 0; i < numBufs; ++i) {
        dataLen += bufs[i].len;
    }
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
            topicsLen +
            CBOR_SIZEOF_LEN(dataLen);
        ret = DPS_TxBufferInit(&req->bufs[2], NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&req->bufs[2], 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[2], DPS_CBOR_KEY_TOPICS);
    }
    if (ret == DPS_OK) {
        ret = DPS_TxBufferAppend(&req->bufs[2], pub->topicsBuf.base, topicsLen);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&req->bufs[2], DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeLength(&req->bufs[2], dataLen, CBOR_BYTES);
    }
    for (i = 0; (ret == DPS_OK) && (i < numBufs); ++i) {
        req->bufs[i + 3].base = bufs[i].base;
        req->bufs[i + 3].eob = bufs[i].base + bufs[i].len;
        req->bufs[i + 3].txPos = req->bufs[i + 3].eob;
    }
    DPS_TxBufferClear(&req->bufs[req->numBufs - 1]);
    if (ret == DPS_OK) {
        if (pub->recipients || node->signer.alg) {
            DPS_RxBuffer aadBuf;
            uint8_t nonce[COSE_NONCE_LEN];

            DPS_TxBufferToRx(&req->bufs[0], &aadBuf);
            DPS_MakeNonce(&pub->pubId, req->sequenceNum, DPS_MSG_TYPE_PUB, nonce);
            DPS_UnlockNode(node);
            if (pub->recipients) {
                ret = COSE_Encrypt(COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                                   pub->recipients, pub->recipientsCount, &aadBuf, &req->bufs[1],
                                   &req->bufs[2], req->numBufs - 3, &req->bufs[req->numBufs - 1],
                                   node->keyStore);
            } else {
                ret = COSE_Sign(&node->signer, &aadBuf, &req->bufs[1], &req->bufs[2], req->numBufs - 3,
                                &req->bufs[req->numBufs - 1], node->keyStore);
            }
            DPS_LockNode(node);
            if (ret == DPS_OK) {
                DPS_DBGPRINT("Publication was COSE serialized\n");
                CBOR_Dump("aad", aadBuf.base, DPS_RxBufferAvail(&aadBuf));
                for (i = 3; i < (req->numBufs - 3); ++i) {
                    CBOR_Dump("cryptText", req->bufs[i].base, DPS_TxBufferUsed(&req->bufs[i]));
                }
            } else {
                DPS_WARNPRINT("COSE_Serialize failed: %s\n", DPS_ErrTxt(ret));
            }
        }
    }
    if (ret != DPS_OK) {
        DPS_TxBufferFree(&req->bufs[0]);
        DPS_TxBufferFree(&req->bufs[1]);
        DPS_TxBufferFree(&req->bufs[2]);
        DPS_TxBufferFree(&req->bufs[req->numBufs - 1]);
        /*
         * Any additional buffers belong to the application
         */
    }
    return ret;
}

DPS_Status DPS_PublishBufs(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, int16_t ttl,
                           DPS_PublishBufsComplete cb, void* data)
{
    DPS_Status ret;
    DPS_Node* node = pub ? pub->node : NULL;
    DPS_PublishRequest* req = NULL;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    if ((!bufs && numBufs) || (numBufs > DPS_BUFS_MAX)) {
        return DPS_ERR_ARGS;
    }
    if (!node) {
        return DPS_ERR_NOT_INITIALIZED;
    }
    if (!node->loop) {
        return DPS_ERR_NOT_STARTED;
    }
    /*
     * Check publication is listed and is local
     */
    if (!IsValidPub(pub) || !(pub->flags & PUB_FLAG_LOCAL)) {
        return DPS_ERR_MISSING;
    }

    req = DPS_CreatePublishRequest(pub, numBufs, cb, data);
    if (!req) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    /*
     * Prevent publication from being destroyed while we are using it.
     * Note that we add a reference to keep the publication alive when
     * we release the node lock for serialization.  The release is
     * necessary as the serialization calls the application's crypto
     * handlers.
     */
    DPS_LockNode(node);
    DPS_PublicationIncRef(pub);
    /*
     * Do some sanity checks for retained publication cancellation
     */
    if (ttl < 0) {
        if (!(pub->flags & PUB_FLAG_RETAINED)) {
            DPS_ERRPRINT("Negative ttl only valid for retained publications\n");
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        if (bufs) {
            DPS_ERRPRINT("Payload not permitted when canceling a retained publication\n");
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        ttl = 0;
        pub->flags |= PUB_FLAG_EXPIRED;
    } else if (ttl == 0) {
        pub->flags &= ~PUB_FLAG_RETAINED;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    } else if (ttl > 0) {
        pub->flags |= PUB_FLAG_RETAINED;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    }
    req->ttl = ttl;
    req->sequenceNum = ++pub->sequenceNum;
    /*
     * Serialize the publication
     */
    ret = DPS_SerializePub(req, bufs, numBufs, ttl);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_QueuePushBack(&pub->sendQueue, &req->queue);
    ++req->refCount;
    uv_async_send(&node->pubsAsync);
Exit:
    DPS_PublicationDecRef(pub);
    DPS_UnlockNode(node);
    if (ret != DPS_OK) {
        DPS_DestroyPublishRequest(req);
    }
    return ret;
}

static void PublishComplete(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                            void* data)
{
    if (numBufs && bufs[0].base) {
        free(bufs[0].base);
    }
}

DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* payload, size_t len, int16_t ttl)
{
    DPS_Status ret;
    DPS_Buffer buf = { NULL, 0 };
    DPS_Buffer* bufs = NULL;
    size_t numBufs = 0;

    DPS_DBGTRACE();

    if (payload && len) {
        buf.base = malloc(len);
        if (!buf.base) {
            return DPS_ERR_RESOURCES;
        }
        memcpy(buf.base, payload, len);
        buf.len = len;
        bufs = &buf;
        numBufs = 1;
    }
    ret = DPS_PublishBufs(pub, bufs, numBufs, ttl, PublishComplete, NULL);
    if (ret != DPS_OK) {
        free(buf.base);
    }
    return ret;
}

DPS_Status DPS_DestroyPublication(DPS_Publication* pub)
{
    DPS_Node* node;
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    node = pub->node;
    DPS_LockNode(node);
    /*
     * Maybe destroying an uninitialized publication
     */
    if (!IsValidPub(pub) || (pub->flags & PUB_FLAG_IS_COPY)) {
        DestroyCopy(pub);
        ret = DPS_OK;
        goto Exit;
    }
    /*
     * Check publication is local
     */
    if (!(pub->flags & PUB_FLAG_LOCAL)) {
        ret = DPS_ERR_MISSING;
        goto Exit;
    }
    FreePublication(node, pub);
    ret = DPS_OK;
Exit:
    DPS_UnlockNode(node);
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
    return pub ? pub->userData : NULL;
}

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

DPS_NetRxBuffer* DPS_PublicationGetNetRxBuffer(const DPS_Publication* pub)
{
    if (pub) {
        return pub->rxBuf;
    }
    return NULL;
}

#ifdef DPS_DEBUG
void DPS_DumpPubs(DPS_Node* node)
{
    if (DPS_Debug) {
        DPS_Publication* pub;
        DPS_PRINT("Node %s:\n", DPS_NodeAddrToString(&node->addr));
        for (pub = node->publications; pub; pub = pub->next) {
            int16_t ttl = 0;
            if (!DPS_QueueEmpty(&pub->retainedQueue)) {
                DPS_PublishRequest* req = (DPS_PublishRequest*)DPS_QueueBack(&pub->retainedQueue);
                ttl = REQ_TTL(req);
            }
            DPS_PRINT("  %s(%d) %s%s%s%s%sttl=%d\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum,
                      pub->flags & PUB_FLAG_LOCAL ? "LOCAL " : "",
                      pub->flags & PUB_FLAG_RETAINED ? "RETAINED " : "",
                      pub->flags & PUB_FLAG_EXPIRED ? "EXPIRED " : "",
                      pub->flags & PUB_FLAG_WAS_FREED ? "WAS_FREED " : "",
                      pub->flags & PUB_FLAG_IS_COPY ? "IS_COPY " : "",
                      ttl);
        }
    }
}
#endif
