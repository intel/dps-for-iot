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
#include "bitvec.h"
#include <dps/private/cbor.h>
#include "compat.h"
#include "cose.h"
#include "coap.h"
#include "pub.h"
#include "sub.h"
#include "history.h"
#include "node.h"
#include "topics.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static void FreeHistory(DPS_Publication* pub);

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

    if (pub->shared->recipientsCount == pub->shared->recipientsCap) {
        newCap = 1;
        if (pub->shared->recipientsCap) {
            newCap = pub->shared->recipientsCap * 2;
        }
        newRecipients = realloc(pub->shared->recipients, newCap * sizeof(COSE_Entity));
        if (!newRecipients) {
            return NULL;
        }
        pub->shared->recipients = newRecipients;
        pub->shared->recipientsCap = newCap;
    }
    if (!DPS_CopyKeyId(&newId, kid)) {
        return NULL;
    }

    recipient = &pub->shared->recipients[pub->shared->recipientsCount];
    recipient->alg = alg;
    recipient->kid = newId;
    ++pub->shared->recipientsCount;
    return recipient;
}

static void RemoveRecipient(DPS_Publication* pub, const DPS_KeyId* kid)
{
    size_t i;

    for (i = 0; i < pub->shared->recipientsCount; ++i) {
        if ((pub->shared->recipients[i].kid.len == kid->len) &&
            (memcmp(pub->shared->recipients[i].kid.id, kid->id, kid->len) == 0)) {
            DPS_ClearKeyId(&pub->shared->recipients[i].kid);
            for (; i < pub->shared->recipientsCount - 1; ++i) {
                pub->shared->recipients[i] = pub->shared->recipients[i + 1];
            }
            memset(&pub->shared->recipients[i], 0, sizeof(pub->shared->recipients[i]));
            --pub->shared->recipientsCount;
            break;
        }
    }
}

static void FreeRecipients(PublicationShared* pub)
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

static DPS_Status CopyRecipients(PublicationShared* dst, const PublicationShared* src)
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

static DPS_Publication* ClonePublication(DPS_Publication* pub)
{
    DPS_Publication* clone = NULL;

    clone = calloc(1, sizeof(DPS_Publication));
    if (!clone) {
        return NULL;
    }
    clone->shared = pub->shared; /* Shallow copy of shared fields */
    clone->flags = PUB_FLAG_LOCAL;
    clone->sequenceNum = pub->sequenceNum;
    return clone;
}

static void FreeTopics(DPS_Publication* pub)
{
    size_t i;

    assert(pub);
    assert(pub->shared);

    if (pub->shared->topics) {
        for (i = 0; i < pub->shared->numTopics; ++i) {
            if (pub->shared->topics[i]) {
                free(pub->shared->topics[i]);
            }
        }
        free(pub->shared->topics);
        pub->shared->topics = NULL;
        pub->shared->numTopics = 0;
    }
}

static DPS_Publication* FreePublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Publication* next = pub->next;

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
        FreeHistory(pub);
        pub->flags = PUB_FLAG_WAS_FREED;
    }
    /*
     * If the ref count is non zero the publication buffers are being referenced
     * by the network layer code so cannot be free yet. FreePublication will be
     * called from OnNetSendComplete() or OnMulticastSendComplete() when the ref
     * count goes to zero.
     */
    if (pub->refCount == 0) {
        DPS_TxBufferFree(&pub->protectedBuf);
        DPS_TxBufferFree(&pub->encryptedBuf);
        assert(pub->shared->refCount > 0);
        if (--pub->shared->refCount == 0) {
            FreeRecipients(pub->shared);
            if (pub->shared->bf) {
                DPS_BitVectorFree(pub->shared->bf);
            }
            DPS_TxBufferFree(&pub->shared->bfBuf);
            DPS_TxBufferFree(&pub->shared->topicsBuf);
            FreeTopics(pub);
            free(pub->shared);
        }
        free(pub);
    }
    return next;
}

static int AddToHistory(DPS_Publication* pub, DPS_Publication* clone)
{
    DPS_Publication** history;
    DPS_Publication* next;

    if (!pub->historyCap) {
        return DPS_FALSE;
    }

    history = &pub->history;
    while (*history && (*history != clone)) {
        history = &(*history)->next;
    }
    if (*history == clone) {
        return DPS_FALSE;
    }
    *history = clone;

    if (pub->historyCount < pub->historyCap) {
        ++pub->historyCount;
    } else {
        next = pub->history->next;
        FreePublication(pub->shared->node, pub->history);
        pub->history = next;
    }
    return DPS_TRUE;
}

static void FreeHistory(DPS_Publication* pub)
{
    DPS_Publication* next;
    while (pub->history) {
        next = pub->history->next;
        FreePublication(pub->shared->node, pub->history);
        pub->history = next;
    }
    pub->historyCount = 0;
}

void DPS_PublicationIncRef(DPS_Publication* pub)
{
    ++pub->refCount;
}

void DPS_PublicationDecRef(DPS_Publication* pub)
{
    assert(pub->refCount != 0);
    if ((--pub->refCount == 0) && (pub->flags & PUB_FLAG_WAS_FREED)) {
        FreePublication(pub->shared->node, pub);
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
    DPS_Publication* nextPubList;

    if (!pub|| !pub->shared->node || !pub->shared->node->loop) {
        return DPS_FALSE;
    }
    node = pub->shared->node;
    DPS_LockNode(node);
    for (pubList = node->publications; pubList; pubList = nextPubList) {
        nextPubList = pubList->next;
        if (pub == pubList) {
            goto Unlock;
        }
        for (pubList = pubList->history; pubList; pubList = pubList->next) {
            if (pub == pubList) {
                goto Unlock;
            }
        }
    }
Unlock:
    DPS_UnlockNode(node);
    return pubList != NULL;
}

const DPS_UUID* DPS_PublicationGetUUID(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return &pub->shared->pubId;
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
        return pub->shared->numTopics;
    } else {
        return 0;
    }
}

const char* DPS_PublicationGetTopic(const DPS_Publication* pub, size_t index)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) && (pub->shared->numTopics > index)) {
        return pub->shared->topics[index];
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_PublicationGetSenderKeyId(const DPS_Publication* pub)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) &&
        (pub->shared->sender.alg != COSE_ALG_RESERVED)) {
        return &pub->shared->sender.kid;
    } else {
        return NULL;
    }
}

const DPS_KeyId* DPS_AckGetSenderKeyId(const DPS_Publication* pub)
{
    if ((IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) &&
        (pub->shared->ack.alg != COSE_ALG_RESERVED)) {
        return &pub->shared->ack.kid;
    } else {
        return NULL;
    }
}

int DPS_PublicationIsAckRequested(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->shared->ackRequested;
    } else {
        return 0;
    }
}

DPS_Node* DPS_PublicationGetNode(const DPS_Publication* pub)
{
    if (IsValidPub(pub) || (pub && (pub->flags & PUB_FLAG_IS_COPY))) {
        return pub->shared->node;
    } else {
        return NULL;
    }
}

static DPS_Status UpdatePubHistory(DPS_Node* node, DPS_Publication* pub)
{
    return DPS_UpdatePubHistory(&node->history, &pub->shared->pubId, pub->sequenceNum,
                                pub->shared->ackRequested, PUB_TTL(node, pub), &pub->shared->senderAddr);
}

typedef struct _SubCandidate {
    DPS_Subscription* sub;
    struct _SubCandidate* next;
} SubCandidate;

/*
 * Check if there is a local subscription for this publication
 * Note that we don't deliver expired publications to the handler.
 */
static DPS_Status CallPubHandlers(DPS_Node* node, DPS_Publication* pub)
{
    static const int32_t EncryptedKeys[] = { DPS_CBOR_KEY_TOPICS, DPS_CBOR_KEY_DATA };
    DPS_Status ret;
    uint8_t nonce[COSE_NONCE_LEN];
    COSE_Entity recipient;
    DPS_Subscription* sub;
    DPS_RxBuffer encryptedBuf;
    DPS_TxBuffer plainTextBuf;
    DPS_RxBuffer aadBuf;
    DPS_RxBuffer cipherTextBuf;
    uint8_t* data = NULL;
    size_t dataLen = 0;
    CBOR_MapState mapState;
    size_t i;
    int candidates = DPS_FALSE;

    DPS_DBGTRACE();

    /*
     * See if the publication is match candidate. We may discover later that
     * this is a false positive when we check if the actual topic strings match.
     */
    DPS_LockNode(node);
    for (sub = node->subscriptions; sub && !candidates; sub = sub->next) {
        candidates = DPS_BitVectorIncludes(pub->shared->bf, sub->bf);
    }
    DPS_UnlockNode(node);
    /*
     * Nothing more to do if we don't have any candidates
     */
    if (!candidates) {
        return DPS_OK;
    }
    /*
     * Try to decrypt the publication
     */
    DPS_MakeNonce(&pub->shared->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);

    DPS_TxBufferToRx(&pub->protectedBuf, &aadBuf);
    DPS_TxBufferToRx(&pub->encryptedBuf, &cipherTextBuf);

    ret = COSE_Decrypt(nonce, &recipient, &aadBuf, &cipherTextBuf, node->keyStore, &pub->shared->sender,
                       &plainTextBuf);
    if (ret == DPS_OK) {
        DPS_DBGPRINT("Publication was decrypted\n");
        CBOR_Dump("plaintext", plainTextBuf.base, DPS_TxBufferUsed(&plainTextBuf));
        DPS_TxBufferToRx(&plainTextBuf, &encryptedBuf);
        /*
         * We will use the same key id when we encrypt the acknowledgement
         */
        if (pub->shared->ackRequested) {
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
                if (AddRecipient(pub, recipient.alg, &pub->shared->sender.kid)) {
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
        DPS_TxBufferToRx(&pub->encryptedBuf, &encryptedBuf);
    } else {
        DPS_WARNPRINT("Failed to decrypt publication - %s\n", DPS_ErrTxt(ret));
        /*
         * This doesn't indicate an error with the message, it may be
         * that the message is not encrypted for this node
         */
        ret = DPS_OK;
        goto Exit;
    }
    ret = DPS_ParseMapInit(&mapState, &encryptedBuf, EncryptedKeys, A_SIZEOF(EncryptedKeys), NULL, 0);
    if (ret != DPS_OK) {
        goto Exit;
    }
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            goto Exit;
        }
        switch (key) {
        case DPS_CBOR_KEY_TOPICS:
            /*
             * Deserialize the topic strings
             */
            ret = CBOR_DecodeArray(&encryptedBuf, &pub->shared->numTopics);
            if (ret != DPS_OK) {
                break;
            }
            if (pub->shared->numTopics == 0) {
                ret = DPS_ERR_INVALID;
                break;
            }
            pub->shared->topics = calloc(pub->shared->numTopics, sizeof(char*));
            if (!pub->shared->topics) {
                ret = DPS_ERR_RESOURCES;
                break;
            }
            for (i = 0; i < pub->shared->numTopics; ++i) {
                char* str;
                size_t sz;
                ret = CBOR_DecodeString(&encryptedBuf, &str, &sz);
                if (ret != DPS_OK) {
                    break;
                }
                pub->shared->topics[i] = strndup(str, sz);
                if (!pub->shared->topics) {
                    ret = DPS_ERR_RESOURCES;
                    break;
                }
            }
            break;
        case DPS_CBOR_KEY_DATA:
            /*
             * Get the pointer to the publication data
             */
            ret = CBOR_DecodeBytes(&encryptedBuf, &data, &dataLen);
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        goto Exit;
    }

    DPS_LockNode(node);
    /*
     * Iterate over the candidates and check that the pub strings are a match
     */
    DPS_Subscription* nextSub;
    for (sub = node->subscriptions; sub != NULL; sub = nextSub) {
        nextSub = sub->next;
        int match;
        if (!DPS_BitVectorIncludes(pub->shared->bf, sub->bf)) {
            continue;
        }
        ret = DPS_MatchTopicList(pub->shared->topics, pub->shared->numTopics, sub->topics,
                                 sub->numTopics, node->separators, DPS_FALSE, &match);
        if (ret != DPS_OK) {
            ret = DPS_OK;
            continue;
        }
        if (match) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            DPS_UnlockNode(node);
            sub->handler(sub, pub, data, dataLen);
            DPS_LockNode(node);
        }
    }
    DPS_UnlockNode(node);

Exit:

    DPS_TxBufferFree(&plainTextBuf);
    /* Publication topics will be invalid now if the publication was encrypted */
    FreeTopics(pub);
    return ret;
}

static DPS_Publication* LookupRetained(DPS_Node* node, DPS_UUID* pubId)
{
    DPS_Publication* pub;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && (DPS_UUIDCompare(&pub->shared->pubId, pubId) == 0)) {
            return pub;
        }
    }
    return NULL;
}

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buf, int multicast)
{
    static const int32_t UnprotectedKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_TTL };
    static const int32_t ProtectedKeys[] = { DPS_CBOR_KEY_TTL, DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_SEQ_NUM,
                                             DPS_CBOR_KEY_ACK_REQ, DPS_CBOR_KEY_BLOOM_FILTER };
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_Publication* pub = NULL;
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
    DPS_EndpointSetPort(ep, port);
    /*
     * Check if this is an update for an existing retained publication
     */
    pub = LookupRetained(node, pubId);
    if (pub) {
        /*
         * Retained publications can only be updated with newer revisions
         */
        if (sequenceNum <= pub->sequenceNum) {
            DPS_DBGPRINT("Publication %s/%d is stale (/%d already retained)\n", DPS_UUIDToString(pubId), sequenceNum, pub->sequenceNum);
            return DPS_ERR_STALE;
        }
    } else {
        /*
         * A stale publication is a publication that has the same or older sequence number than the
         * latest publication with the same pubId.
         */
        if (DPS_PublicationIsStale(&node->history, pubId, sequenceNum)) {
            DPS_DBGPRINT("Publication %s/%d is stale\n", DPS_UUIDToString(pubId), sequenceNum);
            return DPS_ERR_STALE;
        }
        pub = calloc(1, sizeof(DPS_Publication));
        if (!pub) {
            return DPS_ERR_RESOURCES;
        }
        pub->shared = calloc(1, sizeof(PublicationShared));
        if (!pub->shared) {
            free(pub);
            return DPS_ERR_RESOURCES;
        }
        pub->shared->refCount = 1;
        pub->shared->bf = DPS_BitVectorAlloc();
        if (!pub->shared->bf) {
            free(pub->shared);
            free(pub);
            return DPS_ERR_RESOURCES;
        }
        memcpy_s(&pub->shared->pubId, sizeof(pub->shared->pubId), pubId, sizeof(DPS_UUID));
        /*
         * Link in the pub
         */
        pub->next = node->publications;
        node->publications = pub;
        pub->shared->node = node;
    }
    pub->sequenceNum = sequenceNum;
    pub->shared->ackRequested = ackRequested;
    pub->flags |= PUB_FLAG_PUBLISH;
    pub->shared->senderAddr = ep->addr;
    /*
     * Free any existing protected and encrypted buffers
     */
    DPS_TxBufferFree(&pub->protectedBuf);
    DPS_TxBufferFree(&pub->encryptedBuf);
    /*
     * The topics array has pointers into pub->encryptedBuf which are now invalid
     */
    FreeTopics(pub);
    /*
     * We have no reason here to hold onto a node for multicast publishers
     */
    if (!multicast) {
        DPS_LockNode(node);
        ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
        DPS_UnlockNode(node);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    /*
     * A negative TTL is a forced expiration. We don't care about payloads and
     * we don't call local handlers.
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
        ret = DPS_BitVectorDeserialize(pub->shared->bf, &bfBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /*
         * Allocate the protected and encrypted buffers
         */
        ret = DPS_TxBufferInit(&pub->protectedBuf, NULL, buf->rxPos - protectedPtr);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = DPS_TxBufferInit(&pub->encryptedBuf, NULL, DPS_RxBufferAvail(buf));
        if (ret != DPS_OK) {
            goto Exit;
        }
        DPS_TxBufferAppend(&pub->protectedBuf, protectedPtr, buf->rxPos - protectedPtr);
        DPS_TxBufferAppend(&pub->encryptedBuf, buf->rxPos, DPS_RxBufferAvail(buf));
        if (ttl > 0) {
            pub->flags |= PUB_FLAG_RETAINED;
        } else {
            pub->flags &= ~PUB_FLAG_RETAINED;
        }
        ret = CallPubHandlers(node, pub);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    pub->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    UpdatePubHistory(node, pub);
    DPS_UpdatePubs(node, pub);
    return DPS_OK;

Exit:
    /*
     * Delete the publisher node if it is sending bad data
     */
    if (ret == DPS_ERR_INVALID || ret == DPS_ERR_SECURITY) {
        DPS_ERRPRINT("Deleting bad publisher\n");
        DPS_LockNode(node);
        DPS_DeleteRemoteNode(node, pubNode);
        DPS_UnlockNode(node);
    }
    if (pub) {
        DPS_LockNode(node);
        /*
         * TODO - should we be updating the pub history after an error?
         */
        UpdatePubHistory(node, pub);
        FreePublication(node, pub);
        DPS_UnlockNode(node);
    }
    return ret;
}

static void OnSendComplete(DPS_Node* node, DPS_Publication* pub)
{
    int dataSendIsComplete = DPS_FALSE;
    int moreDataInSeries = DPS_FALSE;

    DPS_LockNode(node);
    --pub->numSend;
    dataSendIsComplete = (pub->numSend == 0);
    moreDataInSeries = pub->next && (pub->next->shared == pub->shared);
    DPS_PublicationDecRef(pub);
    DPS_UnlockNode(node);

    if (dataSendIsComplete && moreDataInSeries) {
        DPS_UpdatePubs(node, NULL);
    }
}

static void OnNetSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    DPS_Publication* pub = (DPS_Publication*)appCtx;

    OnSendComplete(node, pub);
    /*
     * Only the first buffer can be freed here
     */
    DPS_OnSendComplete(node, NULL, ep, bufs, 1, status);
}

static void OnMulticastSendComplete(DPS_MulticastSender* sender, void* appCtx, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    DPS_Publication* pub = (DPS_Publication*)appCtx;
    DPS_Node* node = pub->shared->node;

    OnSendComplete(node, pub);
    /*
     * Only the first two buffers can be freed - we don't own the others
     */
    DPS_OnSendComplete(node, NULL, NULL, bufs, 2, status);
}

DPS_Status DPS_SendPublication(DPS_Node* node, DPS_Publication* pub, RemoteNode* remote, int loopback)
{
    DPS_Status ret;
    DPS_TxBuffer buf;
    size_t len;
    int16_t ttl = 0;

    DPS_DBGTRACE();

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }
    if (pub->flags & PUB_FLAG_RETAINED) {
        if (pub->flags & PUB_FLAG_EXPIRED) {
            ttl = -1;
        } else {
            ttl = PUB_TTL(node, pub);
            /*
             * It is possible that a retained publication has expired between
             * being marked to send and getting to this point; if so we
             * silently ignore the publication.
             */
            if (ttl <= 0) {
                return DPS_OK;
            }
        }
    }

    len = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF(uint16_t) +
        CBOR_SIZEOF(int16_t);
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
     * Protected and encrypted maps are already serialized
     */
    if (ret == DPS_OK) {
        uv_buf_t bufs[] = {
            uv_buf_init(NULL, 0),
            uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf)),
            uv_buf_init((char*)pub->protectedBuf.base, DPS_TxBufferUsed(&pub->protectedBuf)),
            uv_buf_init((char*)pub->encryptedBuf.base, DPS_TxBufferUsed(&pub->encryptedBuf)),
        };
        if (remote) {
            ret = DPS_NetSend(node, pub, &remote->ep, bufs + 1, A_SIZEOF(bufs) - 1, OnNetSendComplete);
            if (ret == DPS_OK) {
                /*
                 * Prevent the publication from being freed until the send completes.
                 */
                DPS_PublicationIncRef(pub);
                ++pub->numSend;
                /*
                 * Update history to prevent retained publications from being resent.
                 */
                DPS_UpdatePubHistory(&node->history, &pub->shared->pubId, pub->sequenceNum,
                                     pub->shared->ackRequested, PUB_TTL(node, pub), &remote->ep.addr);
            } else {
                /*
                 * Only the first buffer can be freed here - we don't own the others
                 */
                DPS_SendFailed(node, &remote->ep.addr, bufs + 1, 1, ret);
            }
        } else if (loopback) {
            ret = DPS_LoopbackSend(node, bufs + 1, A_SIZEOF(bufs) - 1);
            /*
             * Only the first buffer can be freed here - we don't own the others
             */
            if (ret == DPS_OK) {
                DPS_NetFreeBufs(bufs + 1, 1);
            } else {
                DPS_SendFailed(node, NULL, bufs + 1, 1, ret);
            }
        } else {
            ret = CoAP_Wrap(bufs, A_SIZEOF(bufs));
            if (ret == DPS_OK) {
                ret = DPS_MulticastSend(node->mcastSender, pub, bufs, A_SIZEOF(bufs), OnMulticastSendComplete);
            }
            if (ret == DPS_OK) {
                /*
                 * Prevent the publication from being freed until the send completes.
                 */
                DPS_PublicationIncRef(pub);
                ++pub->numSend;
            } else {
                /*
                 * Only the first two buffers can be freed - we don't own the others
                 */
                DPS_SendFailed(node, NULL, bufs, 2, ret);
            }
            if (ret == DPS_ERR_NO_ROUTE) {
                /*
                 * Rewrite the error to make DPS_SendPublication a no-op when
                 * there are no multicast interfaces available.
                 */
                DPS_WARNPRINT("DPS_MulticastSend failed - %s\n", DPS_ErrTxt(ret));
                ret = DPS_OK;
            }
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

void DPS_ExpirePub(DPS_Node* node, DPS_Publication* pub)
{
    if (pub->flags & PUB_FLAG_LOCAL) {
        pub->flags &= ~PUB_FLAG_PUBLISH;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    } else  {
        DPS_DBGPRINT("Expiring %spub %s\n", pub->flags & PUB_FLAG_RETAINED ? "retained " : "", DPS_UUIDToString(&pub->shared->pubId));
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
    pub->shared = calloc(1, sizeof(PublicationShared));
    if (!pub->shared) {
        free(pub);
        return NULL;
    }
    pub->shared->refCount = 1;
    DPS_GenerateUUID(&pub->shared->pubId);
    pub->shared->node = node;
    return pub;
}

static void DestroyCopy(DPS_Publication* copy)
{
    if (copy) {
        if (copy->shared) {
            FreeTopics(copy);
            FreeRecipients(copy->shared);
            free(copy->shared);
        }
        free(copy);
    }
}

DPS_Publication* DPS_CopyPublication(const DPS_Publication* pub)
{
    DPS_Publication* copy;
    DPS_Status ret = DPS_ERR_RESOURCES;

    DPS_DBGTRACE();

    if (!pub->shared->node) {
        return NULL;
    }
    copy = calloc(1, sizeof(DPS_Publication));
    if (!copy) {
        DPS_ERRPRINT("malloc failure: no memory\n");
        goto Exit;
    }
    copy->flags = PUB_FLAG_IS_COPY;
    copy->sequenceNum = pub->sequenceNum;
    copy->shared = calloc(1, sizeof(PublicationShared));
    /* Deep copy of shared fields */
    if (!copy->shared) {
        DPS_ERRPRINT("malloc failure: no memory\n");
        goto Exit;
    }
    copy->shared->ackRequested = pub->shared->ackRequested;
    copy->shared->handler = pub->shared->handler;
    copy->shared->pubId = pub->shared->pubId;
    copy->shared->sender = pub->shared->sender;
    if (pub->shared->ackRequested) {
        ret = CopyRecipients(copy->shared, pub->shared);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CopyRecipients failed: %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
    }
    copy->shared->node = pub->shared->node;
    copy->shared->numTopics = pub->shared->numTopics;
    if (pub->shared->numTopics > 0) {
        copy->shared->topics = calloc(pub->shared->numTopics, sizeof(char*));
        if (!copy->shared->topics) {
            DPS_ERRPRINT("malloc failure: no memory\n");
            goto Exit;
        }
        for (int i = 0; i < pub->shared->numTopics; i++) {
            copy->shared->topics[i] = strndup(pub->shared->topics[i], DPS_MAX_TOPIC_STRLEN);
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
    DPS_Node* node = pub ? pub->shared->node : NULL;
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
    if ((pub->flags & PUB_FLAG_IS_COPY) || pub->shared->bf || pub->shared->topics) {
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

    pub->shared->bf = DPS_BitVectorAlloc();
    if (!pub->shared->bf) {
        return DPS_ERR_RESOURCES;
    }
    if (handler) {
        pub->shared->handler = handler;
        pub->shared->ackRequested = DPS_TRUE;
    }
    pub->flags = PUB_FLAG_LOCAL;
    pub->historyCap = 1;
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
            ret = DPS_AddTopic(pub->shared->bf, topics[i], node->separators,
                               noWildCard ? DPS_PubNoWild : DPS_PubTopic);
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    if (ret == DPS_OK) {
        pub->shared->topics = calloc(numTopics, sizeof(char*));
        if (!pub->shared->topics) {
            ret = DPS_ERR_RESOURCES;
        }
        pub->shared->numTopics = numTopics;
    }
    /*
     * Serialize the topics
     */
    if (ret == DPS_OK) {
        size_t bufLen = CBOR_SIZEOF_ARRAY(numTopics);
        for (i = 0; i < numTopics; ++i) {
            bufLen += CBOR_SIZEOF_STRING(topics[i]);
        }
        assert(!pub->shared->topicsBuf.base);
        ret = DPS_TxBufferInit(&pub->shared->topicsBuf, NULL, bufLen);
        if (ret == DPS_OK) {
            ret = CBOR_EncodeArray(&pub->shared->topicsBuf, numTopics);
        }
        if (ret == DPS_OK) {
            for (i = 0; i < numTopics; ++i) {
                ret = CBOR_EncodeString(&pub->shared->topicsBuf, topics[i]);
                if (ret != DPS_OK) {
                    break;
                }
                pub->shared->topics[i] = strdup(topics[i]);
                if (!pub->shared->topics) {
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
        ret = DPS_TxBufferInit(&pub->shared->bfBuf, NULL, 32 + DPS_BitVectorSerializeMaxSize(pub->shared->bf));
        if (ret == DPS_OK) {
            ret = DPS_BitVectorSerialize(pub->shared->bf, &pub->shared->bfBuf);
        }
    }

    if (ret == DPS_OK) {
        DPS_LockNode(node);
        pub->next = node->publications;
        node->publications = pub;
        DPS_UnlockNode(node);
    } else {
        DPS_TxBufferFree(&pub->shared->bfBuf);
        DPS_TxBufferFree(&pub->shared->topicsBuf);
        FreeTopics(pub);
        FreeRecipients(pub->shared);
        if (pub->shared->bf) {
            DPS_BitVectorFree(pub->shared->bf);
            pub->shared->bf = NULL;
        }
    }
    return ret;
}

DPS_Status DPS_PublicationConfigureQoS(DPS_Publication* pub, const DPS_QoS* qos)
{
    DPS_DBGTRACE();

    if (IsValidPub(pub)) {
        pub->historyCap = qos->historyDepth;
        return DPS_OK;
    } else {
        return DPS_ERR_ARGS;
    }
}

DPS_Status DPS_PublicationAddSubId(DPS_Publication* pub, const DPS_KeyId* keyId)
{
    DPS_Status ret;
    int8_t alg;

    DPS_DBGTRACE();

    if (IsValidPub(pub)) {
        DPS_DBGPRINT("Publication has a keyId\n");
        ret = GetRecipientAlgorithm(pub->shared->node->keyStore, keyId, &alg);
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

DPS_Status DPS_SerializePub(DPS_Node* node, DPS_Publication* pub, const uint8_t* data, size_t dataLen, int16_t ttl)
{
    DPS_Status ret;
    size_t len;
    size_t bfLen = DPS_TxBufferUsed(&pub->shared->bfBuf);
    size_t topicsLen = DPS_TxBufferUsed(&pub->shared->topicsBuf);
    DPS_TxBuffer protectedBuf;
    DPS_TxBuffer encryptedBuf;

    /*
     * Encode the protected map
     */
    len = CBOR_SIZEOF_MAP(5) + 5 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_BYTES(sizeof(DPS_UUID)) +
        CBOR_SIZEOF(uint32_t) +
        CBOR_SIZEOF_BOOLEAN() +
        CBOR_SIZEOF_BYTES(bfLen) +
        CBOR_SIZEOF(int16_t);
    ret = DPS_TxBufferInit(&protectedBuf, NULL, len);
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
        ret = CBOR_EncodeBytes(&protectedBuf, (uint8_t*)&pub->shared->pubId, sizeof(pub->shared->pubId));
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
        ret = CBOR_EncodeBoolean(&protectedBuf, pub->shared->ackRequested);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&protectedBuf, DPS_CBOR_KEY_BLOOM_FILTER);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(&protectedBuf, pub->shared->bfBuf.base, bfLen);
    }

    /*
     * Encode the encrypted map
     */
    if (ret == DPS_OK) {
        len = CBOR_SIZEOF_MAP(2) + 2 * CBOR_SIZEOF(uint8_t) +
            topicsLen +
            CBOR_SIZEOF_BYTES(dataLen);
        ret = DPS_TxBufferInit(&encryptedBuf, NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(&encryptedBuf, 2);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&encryptedBuf, DPS_CBOR_KEY_TOPICS);
    }
    if (ret == DPS_OK) {
        ret = DPS_TxBufferAppend(&encryptedBuf, pub->shared->topicsBuf.base, topicsLen);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&encryptedBuf, DPS_CBOR_KEY_DATA);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&encryptedBuf, data, dataLen);
    }
    if (ret != DPS_OK) {
        DPS_TxBufferFree(&protectedBuf);
        return ret;
    }

    if (pub->shared->recipients) {
        DPS_RxBuffer plainTextBuf;
        DPS_RxBuffer aadBuf;
        uint8_t nonce[COSE_NONCE_LEN];

        DPS_TxBufferToRx(&encryptedBuf, &plainTextBuf);
        DPS_TxBufferToRx(&protectedBuf, &aadBuf);
        DPS_MakeNonce(&pub->shared->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);
        ret = COSE_Encrypt(COSE_ALG_A256GCM, nonce, node->signer.alg ? &node->signer : NULL,
                           pub->shared->recipients, pub->shared->recipientsCount, &aadBuf, &plainTextBuf,
                           node->keyStore, &encryptedBuf);
        DPS_RxBufferFree(&plainTextBuf);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
            DPS_TxBufferFree(&protectedBuf);
            return ret;
        }
        DPS_DBGPRINT("Publication was encrypted\n");
        CBOR_Dump("aad", aadBuf.base, DPS_RxBufferAvail(&aadBuf));
        CBOR_Dump("cryptText", encryptedBuf.base, DPS_TxBufferUsed(&encryptedBuf));
    }

    /*
     * This publication may have been queued already so we
     * need to hold the node lock while we replace the buffers
     */
    DPS_LockNode(node);
    assert(pub->refCount == 0);
    DPS_TxBufferFree(&pub->protectedBuf);
    DPS_TxBufferFree(&pub->encryptedBuf);
    pub->protectedBuf = protectedBuf;
    pub->encryptedBuf = encryptedBuf;
    DPS_UnlockNode(node);

    return ret;
}

DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* payload, size_t len, int16_t ttl)
{
    DPS_Status ret;
    DPS_Node* node = pub ? pub->shared->node : NULL;
    DPS_Publication* newClone = NULL;
    DPS_Publication* clone;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
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
    /*
     * Prevent publication from being destroyed while we are cloning
     * it
     */
    DPS_LockNode(node);
    if (pub->history) {
        /*
         * Clone from newest publication data series member so that
         * sequence numbers are correct
         */
        clone = pub->history;
        while (clone->next) {
            clone = clone->next;
        }
    } else {
        clone = pub;
    }
    /*
     * Retained publications overwrite and don't clone
     */
    if (!(clone->flags & PUB_FLAG_RETAINED)) {
        newClone = ClonePublication(clone);
        clone = newClone;
    }
    if (!clone) {
        DPS_UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    clone->flags &= ~PUB_FLAG_PUBLISH;
    clone->checkToSend = DPS_FALSE;
    DPS_UnlockNode(node);
    /*
     * Do some sanity checks for retained publication cancellation
     */
    if (ttl < 0) {
        if (!(clone->flags & PUB_FLAG_RETAINED)) {
            DPS_ERRPRINT("Negative ttl only valid for retained publications\n");
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        if (payload) {
            DPS_ERRPRINT("Payload not permitted when canceling a retained publication\n");
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        ttl = 0;
        clone->flags |= PUB_FLAG_EXPIRED;
    } else {
        clone->flags &= ~PUB_FLAG_RETAINED;
        clone->flags &= ~PUB_FLAG_EXPIRED;
    }
    /*
     * Update time before setting expiration because the loop only updates on each iteration and
     * we have no idea know how long it is since the loop last ran.
     */
    uv_update_time(node->loop);
    clone->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    if (ttl > 0) {
        if (pub->historyCap > 1) {
            DPS_ERRPRINT("History depth > 1 only valid for non-retained publications\n");
            ret = DPS_ERR_INVALID;
            goto Exit;
        }
        clone->flags |= PUB_FLAG_RETAINED;
    }
    ++clone->sequenceNum;
    /*
     * Serialize the publication
     */
    ret = DPS_SerializePub(node, clone, payload, len, ttl);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_LockNode(node);
    clone->flags |= PUB_FLAG_PUBLISH;
    if (AddToHistory(pub, clone)) {
        ++clone->shared->refCount;
    }
    /*
     * Update the (application-visible) publication's sequence number to the latest sequence number
     * so that DPS_PublicationGetSequenceNum works as expected after calling DPS_Publish.
     */
    pub->sequenceNum = clone->sequenceNum;
    newClone = NULL;
    DPS_UnlockNode(node);
    DPS_UpdatePubs(node, clone);
    ret = DPS_OK;

Exit:
    if (newClone) {
        free(newClone);
    }
    return ret;
}

DPS_Status DPS_DestroyPublication(DPS_Publication* pub)
{
    DPS_Node* node;

    DPS_DBGTRACE();

    if (!pub) {
        return DPS_ERR_NULL;
    }
    node = pub->shared->node;
    /*
     * Maybe destroying an uninitialized publication
     */
    if (!IsValidPub(pub) || (pub->flags & PUB_FLAG_IS_COPY)) {
        DestroyCopy(pub);
        return DPS_OK;
    }
    /*
     * Check publication is local
     */
    if (!(pub->flags & PUB_FLAG_LOCAL)) {
        return DPS_ERR_MISSING;
    }
    DPS_LockNode(node);
    FreePublication(node, pub);
    DPS_UnlockNode(node);
    return DPS_OK;
}

DPS_Status DPS_SetPublicationData(DPS_Publication* pub, void* data)
{
    if (pub) {
        pub->shared->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetPublicationData(const DPS_Publication* pub)
{
    return pub ?  pub->shared->userData : NULL;
}

DPS_Publication* DPS_LookupAckHandler(DPS_Node* node, const DPS_UUID* pubId, uint32_t sequenceNum)
{
    DPS_Publication* pub;
    DPS_Publication* history;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->shared->handler && (DPS_UUIDCompare(&pub->shared->pubId, pubId) == 0)) {
            if (pub->sequenceNum == sequenceNum) {
                return pub;
            }
            for (history = pub->history; history; history = history->next) {
                if (history->sequenceNum == sequenceNum) {
                    return history;
                }
            }
        }
    }
    return NULL;
}

#ifdef DPS_DEBUG

/* Maximum number of queued pubs to dump, the rest will be elided */
#define DUMP_PUB_MAX 10

static void DumpPub(DPS_Node* node, DPS_Publication* pub)
{
    int16_t ttl = PUB_TTL(node, pub);
    DPS_PRINT("  %s(%d) %s%s%s%s%s%sttl=%d\n", DPS_UUIDToString(&pub->shared->pubId), pub->sequenceNum,
              pub->flags & PUB_FLAG_PUBLISH ? "PUBLISH " : "",
              pub->flags & PUB_FLAG_LOCAL ? "LOCAL " : "",
              pub->flags & PUB_FLAG_RETAINED ? "RETAINED " : "",
              pub->flags & PUB_FLAG_EXPIRED ? "EXPIRED " : "",
              pub->flags & PUB_FLAG_WAS_FREED ? "WAS_FREED " : "",
              pub->flags & PUB_FLAG_IS_COPY ? "IS_COPY " : "",
              ttl);
}

void DPS_DumpPubs(DPS_Node* node)
{
    if (DPS_Debug) {
        DPS_Publication* pub;
        DPS_Publication* nextPub;
        DPS_PRINT("Node %d:\n", node->port);
        for (pub = node->publications; pub; pub = nextPub) {
            nextPub = pub->next;
            if (pub->history) {
                int i;
                for (i = 0, pub = pub->history; pub && (i < DUMP_PUB_MAX); ++i, pub = pub->next) {
                    DumpPub(node, pub);
                }
                if (pub && (i == DUMP_PUB_MAX)) {
                    DPS_PRINT("  %s(...)\n", DPS_UUIDToString(&pub->shared->pubId));
                }
            } else {
                DumpPub(node, pub);
            }
        }
    }
}
#endif
