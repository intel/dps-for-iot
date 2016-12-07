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
#include "cbor.h"
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

#define RemoteNodeAddressText(n)  DPS_NodeAddrToString(&(n)->ep.addr)

static const char DPS_PublicationURI[] = "dps/pub";

static DPS_Publication* FreePublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Publication* next = pub->next;
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
    if (pub->bf) {
        DPS_BitVectorFree(pub->bf);
    }
    if (pub->payloadLenBuf.base) {
        free(pub->payloadLenBuf.base);
    }
    if (pub->payload.base && !(pub->flags & PUB_FLAG_LOCAL)) {
        free(pub->payload.base);
    }
    if (pub->topics) {
        free(pub->topics);
    }
    if (pub->topicsBuf.base) {
        free(pub->topicsBuf.base);
    }
    free(pub);
    return next;
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
    return IsValidPub(pub) ? &pub->pubId : NULL;
}

uint32_t DPS_PublicationGetSequenceNum(const DPS_Publication* pub)
{
    return IsValidPub(pub) ? pub->sequenceNum : 0;
}

size_t DPS_PublicationGetNumTopics(const DPS_Publication* pub)
{
    return IsValidPub(pub) ? pub->numTopics : 0;
}

const char* DPS_PublicationGetTopic(const DPS_Publication* pub, size_t index)
{
    if (IsValidPub(pub) && (pub->numTopics > index)) {
        return pub->topics[index];
    } else {
        return NULL;
    }
}

static DPS_Status UpdatePubHistory(DPS_Node* node, DPS_Publication* pub)
{
    return DPS_UpdatePubHistory(&node->history, &pub->pubId, pub->sequenceNum, pub->ackRequested, PUB_TTL(node, pub), &pub->sender);
}

/*
 * Check if there is a local subscription for this publication
 * Note that we don't deliver expired publications to the handler.
 */
static void CallPubHandlers(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Subscription* sub;
    DPS_Subscription* next;
    int match;

    DPS_DBGTRACE();

    DPS_LockNode(node);
    for (sub = node->subscriptions; sub != NULL; sub = next) {
        /*
         * Ths current subscription might get freed by the handler so need to hold the next pointer here.
         */
        next = sub->next;
        if (DPS_BitVectorIncludes(pub->bf, sub->bf) &&
            (DPS_MatchTopicList(pub->topics, pub->numTopics, sub->topics, sub->numTopics, node->separators, DPS_FALSE, &match) == DPS_OK) &&
            match) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            /*
             * TODO - make callback from any async
             */
            DPS_UnlockNode(node);
            sub->handler(sub, pub, (uint8_t*)pub->payload.base, pub->payload.len);
            DPS_LockNode(node);
        }
    }
    DPS_UnlockNode(node);
}

DPS_Status CopyPayload(DPS_Publication* pub, DPS_Buffer* in)
{
    uint8_t* begin;
    uint8_t* end;
    size_t len;
    size_t i;
    uint8_t *payload;
    size_t plen;
    DPS_Status ret;

    /*
     * Copy the topic strings
     */
    begin = in->pos;
    ret = CBOR_DecodeArray(in, &pub->numTopics);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (pub->topics) {
        free(pub->topics);
        pub->topics = NULL;
    }
    pub->topics = malloc(pub->numTopics * sizeof(char*));
    if (!pub->topics) {
        goto Exit;
    }
    for (i = 0; i < pub->numTopics; ++i) {
        size_t unused;
        ret = CBOR_DecodeString(in, &pub->topics[i], &unused);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    end = in->pos;
    len = end - begin;
    if (pub->topicsBuf.base) {
        free(pub->topicsBuf.base);
        pub->topicsBuf.base = NULL;
    }
    ret = DPS_BufferInit(&pub->topicsBuf, NULL, len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    memcpy(pub->topicsBuf.base, begin, len);
    pub->topicsBuf.pos += len;
    /*
     * Fixup topics pointers to point into topicsBuf
     */
    for (i = 0; i < pub->numTopics; ++i) {
        ptrdiff_t offset = (uint8_t*)pub->topics[i] - begin;
        pub->topics[i] = (char*)pub->topicsBuf.base + offset;
    }
    /*
     * Then copy the payload length
     */
    begin = in->pos;
    ret = CBOR_DecodeBytes(in, &payload, &plen);
    if (ret != DPS_OK) {
        goto Exit;
    }
    end = in->pos;
    len = end - begin;
    if (pub->payloadLenBuf.base) {
        free(pub->payloadLenBuf.base);
        pub->payloadLenBuf.base = NULL;
    }
    ret = DPS_BufferInit(&pub->payloadLenBuf, NULL, len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    memcpy(pub->payloadLenBuf.base, begin, len);
    pub->payloadLenBuf.pos += len;
    /*
     * And finally the payload
     */
    if (plen) {
        pub->payload.base = realloc(pub->payload.base, plen);
        if (!pub->payload.base) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        memcpy(pub->payload.base, payload, plen);
    } else if (pub->payload.base) {
        free(pub->payload.base);
        pub->payload.base = NULL;
    }
    pub->payload.len = plen;
Exit:
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

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer, int multicast)
{
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_Publication* pub = NULL;
    DPS_UUID* pubId;
    uint32_t sequenceNum;
    int16_t ttl;
    int ackRequested;
    size_t len;

    DPS_DBGTRACE();

    ret = CBOR_DecodeUint16(buffer, &port);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_EndpointSetPort(ep, port);
    ret = CBOR_DecodeInt16(buffer, &ttl);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (len != sizeof(DPS_UUID)) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }
    ret = CBOR_DecodeUint32(buffer, &sequenceNum);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = CBOR_DecodeBoolean(buffer, &ackRequested);
    if (ret != DPS_OK) {
        goto Exit;
    }

    /*
     * See if this is an update for an existing retained publication
     */
    pub = LookupRetained(node, pubId);
    if (pub) {
        /*
         * Retained publications can only be updated with newer revisions
         */
        if (sequenceNum < pub->sequenceNum) {
            DPS_ERRPRINT("Publication is stale");
            return DPS_ERR_STALE;
        }
    } else {
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
     * Stale publications are dropped
     */
    if (DPS_PublicationIsStale(&node->history, pubId, sequenceNum)) {
        DPS_DBGPRINT("Publication %s/%d is stale\n", DPS_UUIDToString(pubId), sequenceNum);
        goto Exit;
    }
    /*
     * We have no reason to hold onto a node for multicast publishers
     */
    if (!multicast) {
        DPS_LockNode(node);
        ret = DPS_AddRemoteNode(node, &ep->addr, ep->cn, DPS_REMOTE_NODE_KEEPALIVE, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
        DPS_UnlockNode(node);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    ret = DPS_BitVectorDeserialize(pub->bf, buffer);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * A negative TTL is a forced expiration. We don't care about payloads and
     * we don't call local handlers.
     */
    if (ttl < 0) {
        if (pub->payload.base) {
            free(pub->payload.base);
            pub->payload.base = NULL;
        }
        pub->payload.len = 0;
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
         * Payload is a pointer into the receive buffer so must be copied
         */
        ret = CopyPayload(pub, buffer);
        if (ret != DPS_OK) {
            goto Exit;
        }
        if (ttl > 0) {
            pub->flags |= PUB_FLAG_RETAINED;
        } else {
            pub->flags &= ~PUB_FLAG_RETAINED;
        }
        /*
         * Forward the publication to matching local subscribers
         */
        CallPubHandlers(node, pub);
    }
    pub->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    UpdatePubHistory(node, pub);
    DPS_UpdatePubs(node, pub);
    return DPS_OK;

Exit:
    /*
     * Delete the publisher node if it is sending bad data
     */
    if (ret == DPS_ERR_INVALID) {
        DPS_ERRPRINT("Deleteing bad publisher\n");
        DPS_LockNode(node);
        DPS_DeleteRemoteNode(node, pubNode);
        DPS_UnlockNode(node);
    }
    if (pub) {
        DPS_LockNode(node);
        UpdatePubHistory(node, pub);
        FreePublication(node, pub);
        DPS_UnlockNode(node);
    }
    return ret;
}

/*
 * Multicast a publication or send it directly to a remote subscriber node
 *
 * COAP header
 * COAP URI PATH
 * Payload (CBOR encoded):
 *      Port publisher is listening on
 *      Publishers IPv6 address (filled in later)
 *      Revision number
 *      Contributor count
 *      Serialized bloom filter
 */
DPS_Status DPS_SendPublication(DPS_Node* node, DPS_Publication* pub, DPS_BitVector* bf, RemoteNode* remote)
{
    DPS_Status ret;
    DPS_Buffer headers;
    DPS_Buffer payload;
    CoAP_Option opts[1];
    int protocol;
    int16_t ttl = 0;

    DPS_DBGTRACE();

    if (pub->flags & PUB_FLAG_RETAINED) {
        if (pub->flags & PUB_FLAG_EXPIRED) {
            ttl = -1;
        } else {
            ttl = PUB_TTL(node, pub);
            /*
             * It is possible that a retained publication has expired between
             * being marked to send and getting to this point. If so we
             * silently ignore the publication.
             */
            if (ttl <= 0) {
                return DPS_OK;
            }
        }
    } 
    if (remote) {
        DPS_DBGPRINT("SendPublication (ttl=%d) to %s\n", ttl, RemoteNodeAddressText(remote));
        protocol = COAP_PROTOCOL;
    } else {
        DPS_DBGPRINT("SendPublication (ttl=%d) as multicast\n", ttl);
        protocol = COAP_OVER_UDP;
    }
    ret = DPS_BufferInit(&payload, NULL, 32 + DPS_BitVectorSerializeMaxSize(bf));
    if (ret != DPS_OK) {
        return ret;
    }
    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_PublicationURI;
    opts[0].len = sizeof(DPS_PublicationURI);
    /*
     * Write the listening port, ttl, pubId, and serial number
     */
    CBOR_EncodeUint16(&payload, node->port);
    CBOR_EncodeInt16(&payload, ttl);
    CBOR_EncodeBytes(&payload, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    CBOR_EncodeUint(&payload, pub->sequenceNum);
    CBOR_EncodeBoolean(&payload, pub->ackRequested);
    ret = DPS_BitVectorSerialize(bf, &payload);
    if (ret == DPS_OK) {
        ret = CoAP_Compose(protocol, COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts),
                           DPS_BufferUsed(&payload) + DPS_BufferUsed(&pub->topicsBuf) + DPS_BufferUsed(&pub->payloadLenBuf) + pub->payload.len,
                           &headers);
    }
    if (ret == DPS_OK) {
        uv_buf_t bufs[] = {
            { (char*)headers.base, DPS_BufferUsed(&headers) },
            { (char*)payload.base, DPS_BufferUsed(&payload) },
            { (char*)pub->topicsBuf.base, DPS_BufferUsed(&pub->topicsBuf) },
            { (char*)pub->payloadLenBuf.base, DPS_BufferUsed(&pub->payloadLenBuf) },
            { pub->payload.base, pub->payload.len }
        };
        if (remote) {
            ret = DPS_NetSend(node, &remote->ep, bufs, A_SIZEOF(bufs), DPS_OnSendComplete);
            if (ret == DPS_OK) {
                UpdatePubHistory(node, pub);
            } else {
                DPS_SendFailed(node, &remote->ep.addr, bufs, A_SIZEOF(bufs), ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs));
            /*
             * Only the first two buffers in a message are allocated
             * per-message.  The others have a longer lifetime.
             */
            DPS_NetFreeBufs(bufs, 2);
        }
    } else {
        free(payload.base);
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
    copy->flags = PUB_FLAG_IS_COPY;
    return copy;
}

DPS_Status DPS_InitPublication(DPS_Publication* pub, const char** topics, size_t numTopics, int noWildCard, DPS_AcknowledgementHandler handler)
{
    size_t i;
    size_t bufLen;
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
    DPS_DumpTopics(topics, numTopics);

    pub->bf = DPS_BitVectorAlloc();
    if (!pub->bf) {
        return DPS_ERR_RESOURCES;
    }
    if (handler) {
        pub->handler = handler;
        pub->ackRequested = DPS_TRUE;
    }
    pub->flags = PUB_FLAG_LOCAL;

    if (ret == DPS_OK) {
        bufLen = CBOR_MAX_LENGTH; /* CBOR array encoding */
        for (i = 0; i < numTopics; ++i) {
            bufLen += CBOR_MAX_LENGTH + strlen(topics[i]) + 1; /* CBOR string encoding */
            ret = DPS_AddTopic(pub->bf, topics[i], node->separators, noWildCard ? DPS_PubNoWild : DPS_PubTopic);
            if (ret != DPS_OK) {
                break;
            }
        }
    }
    if (ret == DPS_OK) {
        pub->topics = malloc(numTopics * sizeof(char*));
        if (pub->topics) {
            pub->numTopics = numTopics;
        } else {
            ret = DPS_ERR_RESOURCES;
        }
    }
    if (ret == DPS_OK) {
        assert(!pub->topicsBuf.base);
        ret = DPS_BufferInit(&pub->topicsBuf, NULL, bufLen);
    }
    if (ret == DPS_OK) {
        CBOR_EncodeArray(&pub->topicsBuf, numTopics);
        for (i = 0; i < numTopics; ++i) {
            size_t len = strlen(topics[i]) + 1;
            CBOR_EncodeLength(&pub->topicsBuf, len, CBOR_STRING);
            pub->topics[i] = (char*)pub->topicsBuf.pos;
            CBOR_Copy(&pub->topicsBuf, (uint8_t*)topics[i], len);
        }
    }
    if (ret == DPS_OK) {
        ret = DPS_BufferInit(&pub->payloadLenBuf, NULL, CBOR_MAX_LENGTH);
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
        if (pub->topics) {
            free(pub->topics);
            pub->topics = NULL;
        }
        if (pub->topicsBuf.base) {
            free(pub->topicsBuf.base);
            pub->topicsBuf.base = NULL;
        }
    }
    return ret;
}

DPS_Status DPS_Publish(DPS_Publication* pub, uint8_t* payload, size_t len, int16_t ttl, uint8_t** oldPayload)
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
    DPS_LockNode(node);
    /*
     * Return the existing payload pointer if requested
     */
    if (oldPayload) {
        *oldPayload = (uint8_t*)pub->payload.base;
    }
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
    }
    /*
     * Encode payload length and save off payload pointer
     */
    DPS_BufferReset(&pub->payloadLenBuf);
    ret = CBOR_EncodeLength(&pub->payloadLenBuf, len, CBOR_BYTES);
    if (ret != DPS_OK) {
        DPS_UnlockNode(node);
        return ret;
    }
    pub->payload.base = (char*)payload;
    pub->payload.len = len;
    pub->flags |= PUB_FLAG_PUBLISH;
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

    DPS_UnlockNode(node);
    DPS_UpdatePubs(node, pub);
    return DPS_OK;
}

DPS_Status DPS_DestroyPublication(DPS_Publication* pub, uint8_t** payload)
{
    DPS_Node* node;

    DPS_DBGTRACE();
    if (!pub) {
        return DPS_ERR_NULL;
    }
    if (payload) {
        *payload = NULL;
    }
    node = pub->node;
    /*
     * Maybe destroying an uninitialized publication
     */
    if (!node || (pub->flags & PUB_FLAG_IS_COPY)) {
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
    if (payload) {
        *payload = (uint8_t*)pub->payload.base;
    }
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

