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
#include <malloc.h>
#include <uv.h>
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

static const char DPS_PublicationURI[] = "dps/pub";

#define RemoteNodeAddressText(n)  DPS_NodeAddrToString(&(n)->ep.addr)

static DPS_Publication* FreePublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Publication* next = pub->next;

    if (!(pub->flags & PUB_FLAG_WAS_FREED)) {
        if (node->publications == pub) {
            node->publications = next;
        } else {
            DPS_Publication* prev = node->publications;
            while (prev->next != pub) {
                prev = prev->next;
                assert(prev);
            }
            prev->next = next;
        }
        if (pub->keyId) {
            free(pub->keyId);
            pub->keyId = NULL;
        }
        if (pub->bf) {
            DPS_BitVectorFree(pub->bf);
            pub->bf = NULL;
        }
        DPS_TxBufferFree(&pub->bfBuf);
        DPS_TxBufferFree(&pub->topicsBuf);
        if (pub->topics) {
            free(pub->topics);
            pub->topics = NULL;
        }
        pub->flags = PUB_FLAG_WAS_FREED;
        pub->next = NULL;
    }
    /*
     * If the ref count is non zero the publication buffers are being referenced
     * by the network layer code so cannot be free yet. FreePublication will be
     * called from OnPubSendComplete() when the ref count goes to zero.
     */
    if (pub->refCount == 0) {
        DPS_TxBufferFree(&pub->body);
        DPS_TxBufferFree(&pub->payload);
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
    DPS_Publication* pubList;

    if (!pub|| !pub->node || !pub->node->loop) {
        return DPS_FALSE;
    }
    DPS_LockNode(pub->node);
    for (pubList = pub->node->publications; pubList != NULL; pubList = pubList->next) {
        if (pub == pubList) {
            break;
        }
    }
    DPS_UnlockNode(pub->node);
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

static DPS_Status GetKey(void* ctx, const DPS_UUID* kid, int8_t alg, uint8_t key[AES_128_KEY_LEN])
{
    DPS_Node* node = (DPS_Node*)ctx;
    DPS_KeyStore* keyStore = node->keyStore;

    if (keyStore && keyStore->contentKeyCB) {
        return keyStore->contentKeyCB(keyStore, kid, key, AES_128_KEY_LEN);
    } else {
        return DPS_ERR_MISSING;
    }
}

static DPS_Status UpdatePubHistory(DPS_Node* node, DPS_Publication* pub)
{
    return DPS_UpdatePubHistory(&node->history, &pub->pubId, pub->sequenceNum, pub->ackRequested, PUB_TTL(node, pub), &pub->sender);
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
    DPS_Status ret;
    uint8_t nonce[DPS_COSE_NONCE_SIZE];
    DPS_UUID keyId;
    DPS_Subscription* sub;
    DPS_RxBuffer payload;
    DPS_TxBuffer plainText;
    DPS_RxBuffer aad;
    DPS_RxBuffer cipherText;
    uint8_t* pubPayload;
    size_t pubPayloadLen;
    size_t len;
    size_t i;
    SubCandidate* candidates = NULL;
    SubCandidate* cdt = NULL;

    DPS_DBGTRACE();

    /*
     * See if the publication is match candidate. We may discover later that
     * this is a false positive when we check if the actual topic strings match.
     */
    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        if (!DPS_BitVectorIncludes(pub->bf, sub->bf)) {
            continue;
        }
        cdt = malloc(sizeof(SubCandidate));
        if (!cdt) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        cdt->sub = sub;
        cdt->next = candidates;
        candidates = cdt;
    }
    /*
     * Nothing more to do if we don't have any candidates
     */
    if (!candidates) {
        return DPS_OK;
    }
    /*
     * Try to decrypt the publication
     */
    DPS_MakeNonce(&pub->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);

    DPS_TxBufferToRx(&pub->body, &aad);
    DPS_TxBufferToRx(&pub->payload, &cipherText);

    ret = COSE_Decrypt(nonce, &keyId, &aad, &cipherText, GetKey, node, &plainText);
    if (ret == DPS_OK) {
        DPS_DBGPRINT("Publication was decrypted\n");
        CBOR_Dump("plaintext", plainText.base, DPS_TxBufferUsed(&plainText));
        DPS_TxBufferToRx(&plainText, &payload);
        /*
         * We will use the same key id when we encrypt the acknowledgement
         */
        if (pub->ackRequested) {
            pub->keyId = malloc(sizeof(DPS_UUID));
            if (!pub->keyId) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            memcpy_s(pub->keyId, sizeof(DPS_UUID), &keyId, sizeof(DPS_UUID));
        }
    } else if (ret == DPS_ERR_NOT_ENCRYPTED) {
        if (node->isSecured) {
            DPS_ERRPRINT("Publication was not encrypted - discarding\n");
            goto Exit;
        }
        /*
         * The payload was not encrypted
         */
        DPS_TxBufferToRx(&pub->payload, &payload);
    } else {
        DPS_ERRPRINT("Failed to decrypt publication - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = CBOR_DecodeArray(&payload, &len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (len != 2) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }
    /*
     * Deserialize the topic strings
     */
    ret = CBOR_DecodeArray(&payload, &pub->numTopics);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (pub->numTopics == 0) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }
    pub->topics = malloc(pub->numTopics * sizeof(char*));
    if (!pub->topics) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    for (i = 0; i < pub->numTopics; ++i) {
        size_t sz;
        ret = CBOR_DecodeString(&payload, &pub->topics[i], &sz);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    /*
     * Get the pointer to the publication data
     */
    ret = CBOR_DecodeBytes(&payload, &pubPayload, &pubPayloadLen);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_LockNode(node);
    /*
     * Iterate over the candidates and check that the pub strings are a match
     */
    for (cdt = candidates; cdt; cdt = cdt->next) {
        int match;
        ret = DPS_MatchTopicList(pub->topics, pub->numTopics, cdt->sub->topics, cdt->sub->numTopics, node->separators, DPS_FALSE, &match);
        if (ret != DPS_OK) {
            ret = DPS_OK;
            continue;
        }
        if (match) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            DPS_UnlockNode(node);
            cdt->sub->handler(cdt->sub, pub, pubPayload, pubPayloadLen);
            DPS_LockNode(node);
        }
    }
    DPS_UnlockNode(node);

Exit:

    while (candidates) {
        cdt = candidates;
        candidates = candidates->next;
        free(cdt);
    }
    DPS_TxBufferFree(&plainText);
    return ret;

}

static DPS_Publication* LookupRetained(DPS_Node* node, DPS_UUID* pubId)
{
    DPS_Publication* pub;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && (DPS_UUIDCompare(&pub->pubId, pubId) == 0)) {
            return pub;
        }
    }
    return NULL;
}

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer, int multicast)
{
    static const int32_t HeaderKeys[] = { DPS_CBOR_KEY_PORT, DPS_CBOR_KEY_TTL };
    static const int32_t BodyKeys[] = { DPS_CBOR_KEY_TTL, DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_SEQ_NUM,
                                        DPS_CBOR_KEY_ACK_REQ, DPS_CBOR_KEY_BLOOM_FILTER };
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_Publication* pub = NULL;
    DPS_UUID* pubId = NULL;
    DPS_RxBuffer bfBuf;
    uint8_t* bodyPtr;
    CBOR_MapState mapState;
    uint32_t sequenceNum;
    int16_t ttl;
    int16_t baseTTL;
    int ackRequested;
    size_t len;

    DPS_DBGTRACE();

    CBOR_Dump("Pub in", buffer->rxPos, DPS_RxBufferAvail(buffer));
    /*
     * Parse keys from header map
     */
    ret = DPS_ParseMapInit(&mapState, buffer, HeaderKeys, A_SIZEOF(HeaderKeys));
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
            ret = CBOR_DecodeUint16(buffer, &port);
            break;
        case DPS_CBOR_KEY_TTL:
            ret = CBOR_DecodeInt16(buffer, &ttl);
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
     * Start of publication body
     */
    bodyPtr = buffer->rxPos;
    /*
     * Parse keys from body map
     */
    ret = DPS_ParseMapInit(&mapState, buffer, BodyKeys, A_SIZEOF(BodyKeys));
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
        case DPS_CBOR_KEY_TTL:
            ret = CBOR_DecodeInt16(buffer, &baseTTL);
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
            ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
            if ((ret == DPS_OK) && (len != sizeof(DPS_UUID))) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_SEQ_NUM:
            ret = CBOR_DecodeUint32(buffer, &sequenceNum);
            if ((ret == DPS_OK) && (sequenceNum == 0)) {
                ret = DPS_ERR_INVALID;
            }
            break;
        case DPS_CBOR_KEY_ACK_REQ:
            ret = CBOR_DecodeBoolean(buffer, &ackRequested);
            break;
        case DPS_CBOR_KEY_BLOOM_FILTER:
            /*
             * Skip the bloom filter for now
             */
            ret = CBOR_Skip(buffer, NULL, &len);
            if (ret == DPS_OK) {
                DPS_RxBufferInit(&bfBuf, buffer->rxPos - len, len);
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
        pub->bf = DPS_BitVectorAlloc();
        if (!pub->bf) {
            free(pub);
            return DPS_ERR_RESOURCES;
        }
        pub->pubId = *pubId;
        /*
         * Link in the pub
         */
        pub->next = node->publications;
        node->publications = pub;
        pub->node = node;
    }
    pub->sequenceNum = sequenceNum;
    pub->ackRequested = ackRequested;
    pub->flags |= PUB_FLAG_PUBLISH;
    pub->sender = ep->addr;
    /*
     * Free any existing body and payload buffers
     */
    DPS_TxBufferFree(&pub->body);
    DPS_TxBufferFree(&pub->payload);
    /*
     * The topics array has pointers into pub->body which are now invalid
     */
    if (pub->topics) {
        free(pub->topics);
        pub->topics = NULL;
        pub->numTopics = 0;
    }
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
        ret = DPS_BitVectorDeserialize(pub->bf, &bfBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /*
         * Allocate the body and payload buffers
         */
        ret = DPS_TxBufferInit(&pub->body, NULL, buffer->rxPos - bodyPtr);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = DPS_TxBufferInit(&pub->payload, NULL, DPS_RxBufferAvail(buffer));
        if (ret != DPS_OK) {
            goto Exit;
        }
        DPS_TxBufferAppend(&pub->body, bodyPtr, buffer->rxPos - bodyPtr);
        DPS_TxBufferAppend(&pub->payload, buffer->rxPos, DPS_RxBufferAvail(buffer));
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
/*
 * TODO - for now we use a CoAP envelope for multicast publications.
 */
static DPS_Status CoAP_Wrap(uv_buf_t* bufs, size_t numBufs)
{
    DPS_Status ret;
    DPS_TxBuffer coap;
    size_t i;
    size_t len = 0;
    CoAP_Option opts[1];

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_PublicationURI;
    opts[0].len = sizeof(DPS_PublicationURI);

    for (i = 1; i < numBufs; ++i) {
        len += bufs[i].len;
    }
    ret =  CoAP_Compose(COAP_OVER_UDP, COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), len, &coap);
    if (ret == DPS_OK) {
        bufs[0].base = (void*)coap.base;
        bufs[0].len = DPS_TxBufferUsed(&coap);
    }
    return ret;
}

static void OnPubSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    DPS_Publication* pub = (DPS_Publication*)appCtx;

    DPS_LockNode(node);
    DPS_PublicationDecRef(pub);
    DPS_UnlockNode(node);
    /*
     * Only the first buffer can be freed here
     */
    DPS_OnSendComplete(node, NULL, ep, bufs, 1, status);
}

/*
 * Multicast a publication or send it directly to a remote subscriber node
 */
DPS_Status DPS_SendPublication(DPS_Node* node, DPS_Publication* pub, RemoteNode* remote)
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
    /*
     * Publication is encoded as an array of 5 elements
     *  [
     *      version,
     *      type,
     *      { headers },
     *      { body }
     *      payload [ topics, data ]
     *  ]
     */
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
     * Header map
     *  {
     *      port: uint
     *      ttl: int
     *  }
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
     * Body and payload are already serialized
     */
    if (ret == DPS_OK) {
        uv_buf_t bufs[] = {
            uv_buf_init(NULL, 0),
            uv_buf_init((char*)buf.base, DPS_TxBufferUsed(&buf)),
            uv_buf_init((char*)pub->body.base, DPS_TxBufferUsed(&pub->body)),
            uv_buf_init((char*)pub->payload.base, DPS_TxBufferUsed(&pub->payload)),
        };
        if (remote) {
            ret = DPS_NetSend(node, pub, &remote->ep, bufs + 1, A_SIZEOF(bufs) - 1, OnPubSendComplete);
            if (ret == DPS_OK) {
                /*
                 * Prevent the publication from being freed until the send completes.
                 */
                ++pub->refCount;
            } else {
                /*
                 * Only the first buffer can be freed here - we don't own the others
                 */
                DPS_SendFailed(node, &remote->ep.addr, bufs + 1, 1, ret);
            }
        } else {
            ret = CoAP_Wrap(bufs, A_SIZEOF(bufs));
            if (ret == DPS_OK) {
                ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs));
            }
            /*
             * Only the first two buffers can be freed - we don't own the others
             */
            DPS_NetFreeBufs(bufs, 2);
        }
        if (ret == DPS_OK) {
            UpdatePubHistory(node, pub);
        }
    } else {
        DPS_TxBufferFree(&buf);
    }
    return ret;
}

/*
 * When a ttl expires retained publications are freed, local
 * publications are disabled by clearing the PUBLISH flag.
 */
void DPS_ExpirePub(DPS_Node* node, DPS_Publication* pub)
{
    if (pub->flags & PUB_FLAG_LOCAL) {
        pub->flags &= ~PUB_FLAG_PUBLISH;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    } else  {
        DPS_DBGPRINT("Expiring %spub %s\n", pub->flags & PUB_FLAG_RETAINED ? "retained " : "", DPS_UUIDToString(&pub->pubId));
        FreePublication(node, pub);
    }
}

DPS_Publication* DPS_CreatePublication(DPS_Node* node)
{
    DPS_Publication* pub;
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
    return pub;
}

DPS_Publication* DPS_CopyPublication(const DPS_Publication* pub)
{
    DPS_Publication* copy;
    if (!pub->node) {
        return NULL;
    }
    if (pub->flags & PUB_FLAG_LOCAL) {
        return NULL;
    }
    copy = calloc(1, sizeof(DPS_Publication));
    if (!copy) {
        return NULL;
    }
    copy->pubId = pub->pubId;
    copy->sequenceNum = pub->sequenceNum;
    copy->node = pub->node;
    copy->ackRequested = pub->ackRequested;
    copy->numTopics = pub->numTopics;
    if (pub->numTopics > 0) {
        copy->topics = malloc(pub->numTopics * sizeof(char*));
        if (!copy->topics) {
            DPS_ERRPRINT("malloc failure: no memory\n");
            return NULL;
        }
        for (int i = 0; i < pub->numTopics; i++) {
            copy->topics[i] = strndup(pub->topics[i], DPS_MAX_TOPIC_STRLEN);
        }
    }
    copy->flags = PUB_FLAG_IS_COPY;
    return copy;
}

DPS_Status DPS_InitPublication(DPS_Publication* pub,
                               const char** topics,
                               size_t numTopics,
                               int noWildCard,
                               const DPS_UUID* keyId,
                               DPS_AcknowledgementHandler handler)
{
    size_t i;
    DPS_Node* node = pub ? pub->node : NULL;
    DPS_Status ret = DPS_OK;

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
        if (!pub->node->isSecured) {
            DPS_ERRPRINT("Node was not enabled for security\n");
            ret = DPS_ERR_SECURITY;
        } else {
            pub->keyId = malloc(sizeof(DPS_UUID));
            if (pub->keyId) {
                memcpy_s(pub->keyId, sizeof(DPS_UUID), keyId, sizeof(DPS_UUID));
            } else {
                ret = DPS_ERR_RESOURCES;
            }
        }
    }
    if (ret == DPS_OK) {
        for (i = 0; i < numTopics; ++i) {
            ret = DPS_AddTopic(pub->bf, topics[i], node->separators, noWildCard ? DPS_PubNoWild : DPS_PubTopic);
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    if (ret == DPS_OK) {
        pub->topics = malloc(numTopics * sizeof(char*));
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
                uint64_t len = strnlen(topics[i], CBOR_MAX_STRING_LEN) + 1;
                if (len > CBOR_MAX_STRING_LEN) {
                    ret = DPS_ERR_OVERFLOW;
                    break;
                }
                ret = CBOR_EncodeLength(&pub->topicsBuf, len, CBOR_STRING);
                if (ret != DPS_OK) {
                    break;
                }
                pub->topics[i] = (char*)pub->topicsBuf.txPos;
                ret = CBOR_Copy(&pub->topicsBuf, (uint8_t*)topics[i], len);
                if (ret != DPS_OK) {
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
        if (pub->bf) {
            DPS_BitVectorFree(pub->bf);
            pub->bf = NULL;
        }
        DPS_TxBufferFree(&pub->topicsBuf);
        DPS_TxBufferFree(&pub->bfBuf);
    }
    return ret;
}

/*
 * Serialize the body and payload sections of a publication
 *
 * The topic strings and bloom filter have already been serialized into buffers in
 * the publication structure,
 */
DPS_Status DPS_SerializePub(DPS_Node* node, DPS_Publication* pub, const uint8_t* data, size_t dataLen, int16_t ttl)
{
    DPS_Status ret;
    size_t len;
    size_t bfLen = DPS_TxBufferUsed(&pub->bfBuf);
    size_t topicsLen = DPS_TxBufferUsed(&pub->topicsBuf);
    DPS_TxBuffer body;
    DPS_TxBuffer payload;

    len = CBOR_SIZEOF_MAP(5) + 5 * CBOR_SIZEOF(uint8_t) +
        CBOR_SIZEOF_BSTR(sizeof(DPS_UUID)) +
        CBOR_SIZEOF(uint32_t) +
        CBOR_SIZEOF_BOOL +
        CBOR_SIZEOF_BSTR(bfLen) +
        CBOR_SIZEOF(int16_t);

    ret = DPS_TxBufferInit(&body, NULL, len);
    if (ret != DPS_OK) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Encode body fields - if encrypting these fields form the external AAD
     */
    ret = CBOR_EncodeMap(&body, 5);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&body, DPS_CBOR_KEY_TTL);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt16(&body, ttl);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&body, DPS_CBOR_KEY_PUB_ID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&body, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&body, DPS_CBOR_KEY_SEQ_NUM);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint32(&body, pub->sequenceNum);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&body, DPS_CBOR_KEY_ACK_REQ);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBoolean(&body, pub->ackRequested);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(&body, DPS_CBOR_KEY_BLOOM_FILTER);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(&body, pub->bfBuf.base, bfLen);
    }
    if (ret == DPS_OK) {
        /*
         * Encode the payload fields - if encrypting these fields are encrypted
         */
        len = CBOR_SIZEOF_ARRAY(2) + topicsLen + CBOR_SIZEOF_BSTR(dataLen);
        ret = DPS_TxBufferInit(&payload, NULL, len);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(&payload, 2);
    }
    if (ret == DPS_OK) {
        ret = DPS_TxBufferAppend(&payload, pub->topicsBuf.base, topicsLen);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(&payload, data, dataLen);
    }
    if (ret != DPS_OK) {
        DPS_TxBufferFree(&body);
        return ret;
    }
    if (node->isSecured) {
        DPS_RxBuffer plainText;
        DPS_RxBuffer aad;
        DPS_UUID* keyId = pub->keyId ? pub->keyId : &node->keyId;
        uint8_t nonce[DPS_COSE_NONCE_SIZE];

        DPS_TxBufferToRx(&payload, &plainText);
        DPS_TxBufferToRx(&body, &aad);
        DPS_MakeNonce(&pub->pubId, pub->sequenceNum, DPS_MSG_TYPE_PUB, nonce);
        ret = COSE_Encrypt(AES_CCM_16_128_128, keyId, nonce, &aad, &plainText, GetKey, node, &payload);
        DPS_RxBufferFree(&plainText);
        if (ret != DPS_OK) {
            DPS_TxBufferFree(&body);
            return ret;
        }
        DPS_DBGPRINT("Publication was encrypted\n");
        CBOR_Dump("aad", aad.base, DPS_RxBufferAvail(&aad));
        CBOR_Dump("cryptText", payload.base, DPS_TxBufferUsed(&payload));
    }
    /*
     * This publication may have been queued already so we
     * need to hold the node lock while we replace the buffers
     */
    DPS_LockNode(node);
    DPS_TxBufferFree(&pub->body);
    DPS_TxBufferFree(&pub->payload);
    pub->body = body;
    pub->payload = payload;
    DPS_UnlockNode(node);

    return ret;
}

DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* payload, size_t len, int16_t ttl)
{
    DPS_Status ret;
    DPS_Node* node = pub ? pub->node : NULL;
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
     * Prevent publication from being sent while it gets updated
     */
    DPS_LockNode(node);
    pub->flags &= ~PUB_FLAG_PUBLISH;
    pub->checkToSend = DPS_FALSE;
    DPS_UnlockNode(node);
    /*
     * Do some sanity checks for retained publication cancellation
     */
    if (ttl < 0) {
        if (!(pub->flags & PUB_FLAG_RETAINED)) {
            DPS_UnlockNode(node);
            DPS_ERRPRINT("Negative ttl only valid for retained publications\n");
            return DPS_ERR_INVALID;
        }
        if (payload) {
            DPS_UnlockNode(node);
            DPS_ERRPRINT("Payload not permitted when canceling a retained publication\n");
            return DPS_ERR_INVALID;
        }
        ttl = 0;
        pub->flags |= PUB_FLAG_EXPIRED;
    } else {
        pub->flags &= ~PUB_FLAG_RETAINED;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    }
    /*
     * Update time before setting expiration because the loop only updates on each iteration and
     * we have no idea know how long it is since the loop last ran.
     */
    uv_update_time(node->loop);
    pub->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    if (ttl > 0) {
        pub->flags |= PUB_FLAG_RETAINED;
    }
    ++pub->sequenceNum;
    /*
     * Serialize the publication
     */
    ret = DPS_SerializePub(node, pub, payload, len, ttl);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_LockNode(node);
    pub->flags |= PUB_FLAG_PUBLISH;
    DPS_UnlockNode(node);
    DPS_UpdatePubs(node, pub);
    return DPS_OK;
}


DPS_Status DPS_DestroyPublication(DPS_Publication* pub)
{
    DPS_Node* node;

    DPS_DBGTRACE();
    if (!pub) {
        return DPS_ERR_NULL;
    }
    node = pub->node;
    /*
     * Maybe destroying an uninitialized publication
     */
    if (!node || (pub->flags & PUB_FLAG_IS_COPY)) {
        if (pub->topics) {
            for (int i = 0; i < pub->numTopics; i++) {
                if (pub->topics[i]) {
                    free(pub->topics[i]);
                }
            }
            free(pub->topics);
        }
        if (pub->keyId) {
            free(pub->keyId);
        }
        free(pub);
        return DPS_OK;
    }
    /*
     * Check publication is listed and is local
     */
    if (!IsValidPub(pub) || !(pub->flags & PUB_FLAG_LOCAL)) {
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

DPS_Node* DPS_GetPublicationNode(const DPS_Publication* pub)
{
    return pub ? pub->node : NULL;
}

#ifndef NDEBUG
void DPS_DumpPubs(DPS_Node* node)
{
    if (DPS_Debug) {
        DPS_Publication* pub;
        DPS_PRINT("Node %d:\n", node->port);
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            int16_t ttl = PUB_TTL(node, pub);
            DPS_PRINT("  %s(%d) %s ttl=%d\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum, pub->flags & PUB_FLAG_RETAINED ? "RETAINED" : "", ttl);
        }
    }
}
#endif
