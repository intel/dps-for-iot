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
#include <math.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include "bitvec.h"
#include "cbor.h"
#include "coap.h"
#include "history.h"
#include "node.h"
#include "topics.h"
#include "uv_extra.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#ifdef DPS_USE_UDP
#define COAP_PROTOCOL COAP_OVER_UDP
#else
#define COAP_PROTOCOL COAP_OVER_TCP
#endif

#define _MIN_(x, y)  (((x) < (y)) ? (x) : (y))


static const char DPS_SubscriptionURI[] = "dps/sub";
static const char DPS_PublicationURI[] = "dps/pub";
static const char DPS_AcknowledgmentURI[] = "dps/ack";

typedef enum { NO_REQ, SUB_REQ, PUB_REQ, ACK_REQ } RequestType;

typedef enum { LINK_OP, UNLINK_OP } OpType;

typedef struct {
    OpType op;
    void* data;
    DPS_Node* node;
    struct _RemoteNode* remote;
    uv_timer_t timer;
    uv_mutex_t mutex;
    union {
        DPS_OnLinkComplete link;
        DPS_OnUnlinkComplete unlink;
        void* cb;
    } on;
} OnOpCompletion;

typedef struct _RemoteNode {
    OnOpCompletion* completion;
    uint8_t linked;                    /* True if this is a node that was explicitly linked */
    struct {
        uint8_t sync;                  /* If TRUE request remote to synchronize interests */
        uint8_t updates;               /* TRUE if updates have been received but not acted on */
        DPS_BitVector* needs;          /* Bit vector of needs received from  this remote node */
        DPS_BitVector* interests;      /* Bit vector of interests received from  this remote node */
    } inbound;
    struct {
        uint8_t sync;                  /* If TRUE synchronize outbound interests with remote node (no deltas) */
        uint8_t checkForUpdates;       /* TRUE if there may be updated interests to send to this remote */
        DPS_BitVector* needs;          /* Needs bit vector sent outbound to this remote node */
        DPS_BitVector* interests;      /* Interests bit vector sent outbound to this remote node */
    } outbound;
    DPS_NetEndpoint ep;
    uint64_t expires;
    /*
     * Remote nodes are doubly linked into a ring
     */
    struct _RemoteNode* prev;
    struct _RemoteNode* next;
} RemoteNode;

/*
 * Acknowledgment packet queued to be sent on node loop
 */
typedef struct _PublicationAck {
    DPS_Buffer headers;
    DPS_Buffer payload;
    DPS_NodeAddress destAddr;
    uint32_t sequenceNum;
    DPS_UUID pubId;
    struct _PublicationAck* next;
} PublicationAck;

/*
 * Struct to hold the state of a local subscription. We hold the topics so we can provide return the topic list when we
 * get a match. We compute the filter so we can forward to outbound subscribers.
 */
typedef struct _DPS_Subscription {
    void* userData;
    DPS_BitVector* needs;           /* Subscription needs */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this subscription */
    DPS_PublicationHandler handler; /* Callback function to be called for a matching publication */
    DPS_Node* node;                 /* Node for this subscription */
    DPS_Subscription* next;
    size_t numTopics;               /* Number of subscription topics */
    char* topics[1];                /* Subscription topics */
} DPS_Subscription;


#define PUB_FLAG_PUBLISH  (0x01) /* The publication should be published */
#define PUB_FLAG_LOCAL    (0x02) /* The publication is local to this node */
#define PUB_FLAG_RETAINED (0x04) /* The publication had a non-zero TTL */
#define PUB_FLAG_EXPIRED  (0x10) /* The publication had a negative TTL */
#define PUB_FLAG_IS_COPY  (0x80) /* This publication is a copy and can only be used for acknowledgements */

/*
 * Notes on the use of the DPS_Publication fields:
 *
 * The pubId identifies a publication that replaces an earlier retained instance of the same publication.
 *
 * The ttl starts when a publication is first published. It may expire before the publication is ever sent.
 * If a publication received by a subscriber has a non-zero ttl is will be retained for later publication
 * until the ttl expires or it is explicitly expired.
 */
typedef struct _DPS_Publication {
    void* userData;
    uint8_t flags;                  /* Internal state flags */
    uint8_t checkToSend;            /* TRUE if this publication should be checked to send */
    uint8_t ackRequested;           /* TRUE if an ack was requested by the publisher */
    uint64_t expires;               /* Time (in milliseconds) that this publication expires */
    uint32_t sequenceNum;           /* Sequence number for this publication */
    DPS_Buffer payloadLenBuf;
    uv_buf_t payload;
    DPS_AcknowledgementHandler handler;
    DPS_UUID pubId;                 /* Publication identifier */
    DPS_NodeAddress sender;         /* for retained messages - the sender address */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Node* node;                 /* Node for this publication */
    char** topics;                  /* Publication topics */
    size_t numTopics;
    DPS_Buffer topicsBuf;
    DPS_Publication* next;
} DPS_Publication;


#define PUB_TTL(node, pub)  (int16_t)((pub->expires + 999 - uv_now((node)->loop)) / 1000)


#define SEND_SUBS_TASK  0x01
#define SEND_PUBS_TASK  0x02
#define SEND_ACKS_TASK  0x04
#define STOP_NODE_TASK  0x08
#define FIND_ADDR_TASK  0x10

/*
 * If we have not heard anything from a remote node within the
 * keep alive time period it may be deleted. The keep alive
 * time is specified in seconds.
 */
#define REMOTE_NODE_KEEPALIVE  360

/*
 * How long (in milliseconds) to wait to received a response from a remote
 * node this node is linking with.
 */
#define LINK_RESPONSE_TIMEOUT  5000

/*
 * Forward declaration
 */
static void RunBackgroundTasks(uv_async_t* handle);

void LockNode(DPS_Node* node)
{
    uv_mutex_lock(&node->nodeMutex);
#ifndef NDEBUG
    ++node->lockCount;
    assert(node->lockCount == 1);
#endif
}

void UnlockNode(DPS_Node* node)
{
#ifndef NDEBUG
    assert(node->lockCount == 1);
    --node->lockCount;
#endif
    uv_mutex_unlock(&node->nodeMutex);
}

static void ScheduleBackgroundTask(DPS_Node* node, uint8_t task)
{
    DPS_DBGTRACE();
    node->tasks |= task;
    UnlockNode(node);
    uv_async_send(&node->bgHandler);
    LockNode(node);
}

#ifdef NDEBUG
#define DumpTopics(t, n)
#else
static void DumpTopics(const char** topics, size_t numTopics)
{
    if (DPS_Debug) {
        size_t i;
        for (i = 0; i < numTopics; ++i) {
            DPS_PRINT("%s\n", topics[i]);
        }
    }
}
#endif

#ifdef NDEBUG
#define DumpPubs(node)
#else
static void DumpPubs(DPS_Node* node)
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

#define SameUUID(u1, u2)  (memcmp((u1), (u2), sizeof(DPS_UUID)) == 0)

#define RemoteNodeAddressText(n)  DPS_NodeAddrToString(&(n)->ep.addr)


static int IsValidSub(const DPS_Subscription* sub)
{
    DPS_Subscription* subList;

    if (!sub || !sub->node || !sub->node->loop) {
        return DPS_FALSE;
    }
    LockNode(sub->node);
    for (subList = sub->node->subscriptions; subList != NULL; subList = subList->next) {
        if (sub == subList) {
            break;
        }
    }
    UnlockNode(sub->node);
    return subList != NULL;
}

static int IsValidPub(const DPS_Publication* pub)
{
    DPS_Publication* pubList;

    if (!pub|| !pub->node || !pub->node->loop) {
        return DPS_FALSE;
    }
    LockNode(pub->node);
    for (pubList = pub->node->publications; pubList != NULL; pubList = pubList->next) {
        if (pub == pubList) {
            break;
        }
    }
    UnlockNode(pub->node);
    return pubList != NULL;
}

size_t DPS_SubscriptionGetNumTopics(const DPS_Subscription* sub)
{
    return IsValidSub(sub) ? sub->numTopics : 0;
}

const char* DPS_SubscriptionGetTopic(const DPS_Subscription* sub, size_t index)
{
    if (IsValidSub(sub) && (sub->numTopics > index)) {
        return sub->topics[index];
    } else {
        return NULL;
    }
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

static void EndpointSetPort(DPS_NetEndpoint* ep, uint16_t port)
{
    port = htons(port);
    if (ep->addr.inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)&ep->addr.inaddr;
        ip6->sin6_port = port;
    } else {
        struct sockaddr_in* ip4 = (struct sockaddr_in*)&ep->addr.inaddr;
        ip4->sin_port = port;
    }
}

DPS_Status DPS_BufferInit(DPS_Buffer* buffer, uint8_t* storage, size_t size)
{
    DPS_Status ret = DPS_OK;
    if (!storage && size) {
        storage = malloc(size);
        if (!storage) {
            ret = DPS_ERR_RESOURCES;
            size = 0;
        }
    }
    buffer->base = storage;
    buffer->pos = storage;
    buffer->eod = storage + size;
    return ret;
}

DPS_Status DPS_BufferAppend(DPS_Buffer* buffer, const uint8_t* data, size_t len)
{
    if (DPS_BufferSpace(buffer) < len) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(buffer->pos, data, len);
    buffer->pos += len;
    return DPS_OK;
}

static DPS_Subscription* FreeSubscription(DPS_Subscription* sub)
{
    DPS_Subscription* next = sub->next;
    DPS_BitVectorFree(sub->bf);
    DPS_BitVectorFree(sub->needs);
    while (sub->numTopics) {
        free(sub->topics[--sub->numTopics]);
    }
    free(sub);
    return next;
}

static RemoteNode* DeleteRemoteNode(DPS_Node* node, RemoteNode* remote);

static void OnTimerClosed(uv_handle_t* handle)
{
    free(handle->data);
}

static void RemoteCompletion(DPS_Node* node, RemoteNode* remote, DPS_Status status)
{
    OnOpCompletion* cpn = remote->completion;
    DPS_NodeAddress addr = remote->ep.addr;

    uv_timer_stop(&cpn->timer);

    remote->completion = NULL;
    UnlockNode(node);
    if (cpn->op == LINK_OP) {
        cpn->on.link(node, &addr, status, cpn->data);
    } else if (cpn->op == UNLINK_OP) {
        cpn->on.unlink(node, &addr, cpn->data);
    }
    LockNode(node);
    uv_close((uv_handle_t*)&cpn->timer, OnTimerClosed);
    if (status != DPS_OK) {
        DeleteRemoteNode(node, remote);
    }
}

static int IsValidRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    RemoteNode* r = node->remoteNodes;

    while (r) {
        if (r == remote) {
            return DPS_TRUE;
        }
        r = r->next;
    }

    return DPS_FALSE;
}

static RemoteNode* DeleteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    RemoteNode* next;

    DPS_DBGTRACE();

    if (!IsValidRemoteNode(node, remote)) {
        return NULL;
    }
    next = remote->next;
    if (node->remoteNodes == remote) {
        node->remoteNodes = next;
    } else {
        RemoteNode* prev = node->remoteNodes;
        while (prev->next != remote) {
            prev = prev->next;
            assert(prev);
        }
        prev->next = next;
    }
    if (remote->inbound.interests) {
        if (DPS_CountVectorDel(node->interests, remote->inbound.interests) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.interests);
    }
    if (remote->inbound.needs) {
        if (DPS_CountVectorDel(node->needs, remote->inbound.needs) != DPS_OK) {
            assert(!"Count error");
        }
        DPS_BitVectorFree(remote->inbound.needs);
    }
    DPS_BitVectorFree(remote->outbound.interests);
    DPS_BitVectorFree(remote->outbound.needs);

    if (remote->completion) {
        RemoteCompletion(node, remote, DPS_ERR_FAILURE);
    }
    /*
     * This tells the network layer we no longer need to keep connection alive for this address
     */
    DPS_NetConnectionDecRef(remote->ep.cn);
    free(remote);
    return next;
}

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

static DPS_Status UpdateOutboundInterests(DPS_Node* node, RemoteNode* destNode, DPS_BitVector** outboundInterests)
{
    DPS_Status ret;
    DPS_BitVector* newInterests = NULL;
    DPS_BitVector* newNeeds = NULL;

    DPS_DBGTRACE();

    /*
     * Inbound interests from the node we are updating are excluded from the outbound interests
     */
    if (destNode->inbound.interests) {
        ret = DPS_CountVectorDel(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        newInterests = DPS_CountVectorToUnion(node->interests);
        ret = DPS_CountVectorAdd(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        ret = DPS_CountVectorDel(node->needs, destNode->inbound.needs);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        newNeeds = DPS_CountVectorToIntersection(node->needs);
        ret = DPS_CountVectorAdd(node->needs, destNode->inbound.needs);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
    } else {
        assert(!destNode->inbound.needs);
        newInterests = DPS_CountVectorToUnion(node->interests);
        newNeeds = DPS_CountVectorToIntersection(node->needs);
    }
    if (!newNeeds || !newInterests) {
        ret = DPS_ERR_RESOURCES;
        goto ErrExit;
    }
    /*
     * Don't compute the delta if we are synchronizing outbound interests
     */
    if (destNode->outbound.sync) {
        DPS_BitVectorFree(destNode->outbound.interests);
        destNode->outbound.interests = NULL;
    }
    if (destNode->outbound.interests) {
        int same = DPS_FALSE;
        DPS_BitVectorXor(node->scratch.interests, destNode->outbound.interests, newInterests, &same);
        if (same && DPS_BitVectorEquals(destNode->outbound.needs, newNeeds)) {
            *outboundInterests = NULL;
        } else {
            *outboundInterests = node->scratch.interests;
        }
        DPS_BitVectorFree(destNode->outbound.interests);
        DPS_BitVectorFree(destNode->outbound.needs);
    } else {
        /*
         * Inform receiver we are sycnronizing interests
         */
        destNode->outbound.sync = DPS_TRUE;
        *outboundInterests = newInterests;
    }
    destNode->outbound.interests = newInterests;
    destNode->outbound.needs = newNeeds;

    DPS_DBGPRINT("UpdateOutboundInterests: %s %s\n", RemoteNodeAddressText(destNode), *outboundInterests ? "Changes" : "No Change");
    return DPS_OK;

ErrExit:
    DPS_ERRPRINT("UpdateOutboundInterests: %s\n", DPS_ErrTxt(ret));
    DPS_BitVectorFree(newInterests);
    DPS_BitVectorFree(newNeeds);
    return ret;
}

static RemoteNode* LookupRemoteNode(DPS_Node* node, DPS_NodeAddress* addr)
{
    RemoteNode* remote;

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        if (DPS_SameAddr(&remote->ep.addr, addr)) {
            return remote;
        }
    }
    return NULL;
}

static void OnCompletionTimeout(uv_timer_t* timer)
{
    OnOpCompletion* cpn = (OnOpCompletion*)timer->data;
    LockNode(cpn->node);
    RemoteCompletion(cpn->node, cpn->remote, DPS_ERR_TIMEOUT);
    UnlockNode(cpn->node);
}

static OnOpCompletion* AllocCompletion(DPS_Node* node, RemoteNode* remote, OpType op, void* data, uint16_t ttl, void* cb)
{
    OnOpCompletion* cpn;

    cpn = calloc(1, sizeof(OnOpCompletion));
    if (cpn) {
        cpn->op = op;
        cpn->data = data;
        cpn->node = node;
        cpn->remote = remote;
        cpn->on.cb = cb;

        if (uv_timer_init(node->loop, &cpn->timer)) {
            free(cpn);
            return NULL;
        }
        cpn->timer.data = cpn;
        if (uv_timer_start(&cpn->timer, OnCompletionTimeout, ttl, 0)) {
            uv_close((uv_handle_t*)&cpn->timer, OnTimerClosed);
            return NULL;
        }
    }
    return cpn;
}

/*
 * Add a remote node or return an existing one
 */
static DPS_Status AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, DPS_NetConnection* cn, uint16_t ttl, RemoteNode** remoteOut)
{
    RemoteNode* remote = LookupRemoteNode(node, addr);
    if (remote) {
        /*
         * If the remote node has not been explicitly expired we extend the lifetime
         */
        if (remote->expires) {
            remote->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
        }
        *remoteOut = remote;
        /*
         * AddRef a newly established connection
         */
        if (cn && !remote->ep.cn) {
            DPS_NetConnectionAddRef(cn);
            remote->ep.cn = cn;
        }
        return DPS_ERR_EXISTS;
    }
    /*
     * Don't add an already expired remote node
     */
    if (ttl == 0) {
        return DPS_ERR_EXPIRED;
    }
    remote = calloc(1, sizeof(RemoteNode));
    if (!remote) {
        *remoteOut = NULL;
        return DPS_ERR_RESOURCES;
    }
    DPS_DBGPRINT("Adding new remote node %s\n", DPS_NodeAddrToString(addr));
    remote->ep.addr = *addr;
    remote->ep.cn = cn;
    remote->next = node->remoteNodes;
    remote->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    node->remoteNodes = remote;
    /*
     * This tells the network layer to keep connection alive for this address
     */
    DPS_NetConnectionAddRef(cn);
    *remoteOut = remote;
    return DPS_OK;
}

static DPS_Publication* LookupRetained(DPS_Node* node, DPS_UUID* pubId)
{
    DPS_Publication* pub;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && SameUUID(&pub->pubId, pubId)) {
            return pub;
        }
    }
    return NULL;
}

static void FreeBufs(uv_buf_t* bufs, size_t numBufs)
{
    while (numBufs--) {
        if (bufs->base) {
            free(bufs->base);
        }
        ++bufs;
    }
}

static void FreeMessage(uv_buf_t* bufs, size_t numBufs)
{
    /*
     * Only the first two buffers in a message are allocated
     * per-message.  The others have a longer lifetime.
     */
    assert(numBufs >= 2);
    FreeBufs(bufs, 2);
}

static void NetSendFailed(DPS_Node* node, DPS_NodeAddress* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    RemoteNode* remote;

    DPS_DBGPRINT("NetSend failed %s\n", DPS_ErrTxt(status));
    remote = LookupRemoteNode(node, addr);
    if (remote) {
        DeleteRemoteNode(node, remote);
        DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(addr));
    }
    FreeMessage(bufs, numBufs);
}

static void OnNetSendComplete(DPS_Node* node, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        RemoteNode* remote;

        LockNode(node);
        remote = LookupRemoteNode(node, &ep->addr);
        DPS_DBGPRINT("OnNetSendComplete %s\n", DPS_ErrTxt(status));
        if (remote) {
            DeleteRemoteNode(node, remote);
            DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&ep->addr));
        }
        UnlockNode(node);
    }
    FreeMessage(bufs, numBufs);
}

/*
 * Add this publication to the history record
 */
static DPS_Status UpdatePubHistory(DPS_Node* node, DPS_Publication* pub)
{
    return DPS_UpdatePubHistory(&node->history, &pub->pubId, pub->sequenceNum, pub->ackRequested, PUB_TTL(node, pub), &pub->sender);
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
static DPS_Status SendPublication(DPS_Node* node, DPS_Publication* pub, DPS_BitVector* bf, RemoteNode* remote)
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
            ret = DPS_NetSend(node, &remote->ep, bufs, A_SIZEOF(bufs), OnNetSendComplete);
            if (ret == DPS_OK) {
                UpdatePubHistory(node, pub);
            } else {
                NetSendFailed(node, &remote->ep.addr, bufs, A_SIZEOF(bufs), ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs));
            FreeMessage(bufs, A_SIZEOF(bufs));
        }
    } else {
        free(payload.base);
    }
    return ret;
}

static DPS_BitVector* PubSubMatch(DPS_Node* node, DPS_Publication* pub, RemoteNode* subscriber)
{
    DPS_BitVectorIntersection(node->scratch.interests, pub->bf, subscriber->inbound.interests);
    DPS_BitVectorFuzzyHash(node->scratch.needs, node->scratch.interests);
    if (DPS_BitVectorIncludes(node->scratch.needs, subscriber->inbound.needs)) {
        /*
         * If the publication will be retained we send the full publication Bloom
         * filter otherwise we only send the intersection with the subscription interests.
         * The reason for sending the full publication is that we don't know what the
         * interests will be over the lifetime of the publication.
         */
        return (pub->flags & PUB_FLAG_RETAINED) ? pub->bf : node->scratch.interests;
    } else {
        return NULL;
    }
}

static DPS_Status SendMatchingPubToSub(DPS_Node* node, DPS_Publication* pub, RemoteNode* subscriber)
{
    /*
     * We don't send publications to remote nodes we have received them from.
     */
    if (!DPS_PublicationReceivedFrom(&node->history, &pub->pubId, pub->sequenceNum, &pub->sender, &subscriber->ep.addr)) {
        DPS_BitVector* pubBV = PubSubMatch(node, pub, subscriber);
        if (pubBV) {
            DPS_DBGPRINT("Sending pub %d to %s\n", pub->sequenceNum, RemoteNodeAddressText(subscriber));
            return SendPublication(node, pub, pubBV, subscriber);
        }
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->sequenceNum, RemoteNodeAddressText(subscriber));
    }
    return DPS_OK;
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

static DPS_Status QueuePublicationAck(DPS_Node* node, PublicationAck* ack, uint8_t* data, size_t len, DPS_NodeAddress* destAddr)
{
    DPS_Status ret;
    CoAP_Option opts[1];
    size_t allocSize = 8 + sizeof(DPS_UUID) + sizeof(uint32_t) + len;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_AcknowledgmentURI;
    opts[0].len = sizeof(DPS_AcknowledgmentURI);

    ret = DPS_BufferInit(&ack->payload, NULL, allocSize);
    if (ret != DPS_OK) {
        free(ack);
        return ret;
    }
    CBOR_EncodeBytes(&ack->payload, (uint8_t*)&ack->pubId, sizeof(DPS_UUID));
    CBOR_EncodeUint32(&ack->payload, ack->sequenceNum);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&ack->payload, data, len);
        ret = CoAP_Compose(COAP_PROTOCOL, COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), DPS_BufferUsed(&ack->payload), &ack->headers);
        if (ret != DPS_OK) {
            free(ack->payload.base);
            free(ack);
        } else {
            LockNode(node);
            ack->destAddr = *destAddr;
            if (node->ackQueue.last) {
                node->ackQueue.last->next = ack;
            }
            node->ackQueue.last = ack;
            if (!node->ackQueue.first) {
                node->ackQueue.first = ack;
            }
            ScheduleBackgroundTask(node, SEND_ACKS_TASK);
            UnlockNode(node);
        }
    }
    return ret;
}

static DPS_Status DecodeAcknowledgment(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_Publication* pub;
    uint32_t sn;
    uint32_t sequenceNum;
    DPS_UUID* pubId;
    DPS_NodeAddress* addr;
    uint8_t* payload;
    size_t len;

    DPS_DBGTRACE();

    ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (len != sizeof(DPS_UUID)) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeUint32(buffer, &sequenceNum);
    if (ret != DPS_OK) {
        return ret;
    }
    if (sequenceNum == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &payload, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    LockNode(node);
    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->handler && (pub->sequenceNum == sequenceNum) && SameUUID(&pub->pubId, pubId)) {
            break;
        }
    }
    if (pub) {
        if (pub->handler) {
            UnlockNode(node);
            pub->handler(pub, payload, len);
            LockNode(node);
        }
        UnlockNode(node);
        return DPS_OK;
    }
    UnlockNode(node);
    /*
     * Look for in the history record for somewhere to forward the ACK
     */
    ret = DPS_LookupPublisher(&node->history, pubId, &sn, &addr);
    if ((ret == DPS_OK) && (sequenceNum <= sn) && addr) {
        PublicationAck* ack = AllocPubAck(pubId, sequenceNum);
        if (ack) {
            DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), sequenceNum, DPS_NodeAddrToString(addr));
            ret = QueuePublicationAck(node, ack, payload, len, addr);
        } else {
            ret = DPS_ERR_RESOURCES;
        }
    }
    return ret;
}

static void SendAcksTask(DPS_Node* node)
{
    PublicationAck* ack;

    DPS_DBGTRACE();

    while ((ack = node->ackQueue.first) != NULL) {
        RemoteNode* ackNode;
        DPS_Status ret = AddRemoteNode(node, &ack->destAddr, NULL, REMOTE_NODE_KEEPALIVE, &ackNode);
        if (ret == DPS_OK || ret == DPS_ERR_EXISTS) {
            uv_buf_t bufs[] = {
                { (char*)ack->headers.base, DPS_BufferUsed(&ack->headers) },
                { (char*)ack->payload.base, DPS_BufferUsed(&ack->payload) }
            };
            ret = DPS_NetSend(node, &ackNode->ep, bufs, A_SIZEOF(bufs), OnNetSendComplete);
            if (ret != DPS_OK) {
                NetSendFailed(node, &ack->destAddr, bufs, A_SIZEOF(bufs), ret);
            }
        }
        node->ackQueue.first = ack->next;
        free(ack);
    }
    node->ackQueue.last = NULL;
}

/*
 * When a ttl expires retained publications are freed, local
 * publications are disabled by clearing the PUBLISH flag.
 */
static void ExpirePub(DPS_Node* node, DPS_Publication* pub)
{
    if (pub->flags & PUB_FLAG_LOCAL) {
        pub->flags &= ~PUB_FLAG_PUBLISH;
        pub->flags &= ~PUB_FLAG_EXPIRED;
    } else  {
        DPS_DBGPRINT("Expiring %spub %s\n", pub->flags & PUB_FLAG_RETAINED ? "retained " : "", DPS_UUIDToString(&pub->pubId));
        FreePublication(node, pub);
    }
}

static void SendPubsTask(DPS_Node* node)
{
    DPS_Publication* pub;
    DPS_Publication* nextPub;

    DPS_DBGTRACE();

    /*
     * Check if any local or retained publications need to be forwarded to this subscriber
     */
    for (pub = node->publications; pub != NULL; pub = nextPub) {
        nextPub = pub->next;
        /*
         * Only check publications that are flagged to be checked
         */
        if (pub->checkToSend) {
            DPS_Status ret;
            RemoteNode* remote;
            RemoteNode* nextRemote;
            /*
             * If the node is a multicast sender local publications are always multicast
             */
            if (node->mcastSender && (pub->flags & PUB_FLAG_LOCAL)) {
                ret = SendPublication(node, pub, pub->bf, NULL);
                if (ret != DPS_OK) {
                    DPS_ERRPRINT("SendPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
                }
            }
            for (remote = node->remoteNodes; remote != NULL; remote = nextRemote) {
                nextRemote = remote->next;
                if (remote->inbound.interests) {
                    ret = SendMatchingPubToSub(node, pub, remote);
                    if (ret != DPS_OK) {
                        DeleteRemoteNode(node, remote);
                        DPS_ERRPRINT("SendMatchingPubToSub failed %s\n", DPS_ErrTxt(ret));
                    }
                }
            }
            pub->checkToSend = DPS_FALSE;
        }
        if (uv_now(node->loop) >= pub->expires) {
            ExpirePub(node, pub);
        }
    }
    DumpPubs(node);
}

/*
 * Run checks of one or more publications against the current subscriptions
 */
static void SendPubs(DPS_Node* node, DPS_Publication* pub)
{
    int count = 0;
    LockNode(node);

    if (pub) {
        pub->checkToSend = DPS_TRUE;
        ++count;
    } else {
        DPS_Publication* pubNext;
        for (pub = node->publications; pub != NULL; pub = pubNext) {
            pubNext = pub->next;
            /*
             * Received publications are marked as checkToSend they should not be expired.
             */
            if (pub->checkToSend) {
                ++count;
                continue;
            }
            if (uv_now(node->loop) >= pub->expires) {
                ExpirePub(node, pub);
            } else {
                if ((pub->flags & PUB_FLAG_PUBLISH) && (node->remoteNodes || node->mcastSender)) {
                    pub->checkToSend = DPS_TRUE;
                    ++count;
                }
            }
        }
    }
    if (count) {
        DPS_DBGPRINT("SendPubs %d publications to send\n", count);
        ScheduleBackgroundTask(node, SEND_PUBS_TASK);
    }
    UnlockNode(node);
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

    LockNode(node);
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
            UnlockNode(node);
            sub->handler(sub, pub, (uint8_t*)pub->payload.base, pub->payload.len);
            LockNode(node);
        }
    }
    UnlockNode(node);
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

static DPS_Status DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer, int multicast)
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
    EndpointSetPort(ep, port);
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
        LockNode(node);
        ret = AddRemoteNode(node, &ep->addr, ep->cn, REMOTE_NODE_KEEPALIVE, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
        UnlockNode(node);
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
    SendPubs(node, pub);
    return DPS_OK;

Exit:
    /*
     * Delete the publisher node if it is sending bad data
     */
    if (ret == DPS_ERR_INVALID) {
        DPS_ERRPRINT("Deleteing bad publisher\n");
        LockNode(node);
        DeleteRemoteNode(node, pubNode);
        UnlockNode(node);
    }
    if (pub) {
        LockNode(node);
        UpdatePubHistory(node, pub);
        FreePublication(node, pub);
        UnlockNode(node);
    }
    return ret;
}

static DPS_Status SendSubscription(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, uint16_t ttl)
{
    DPS_Status ret;
    CoAP_Option opts[1];
    DPS_Buffer headers;
    DPS_Buffer payload;
    DPS_BitVector* needs = remote->outbound.needs;

    size_t allocSize = DPS_BitVectorSerializeMaxSize(needs) + DPS_BitVectorSerializeMaxSize(interests) + 40;

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_SubscriptionURI;
    opts[0].len = sizeof(DPS_SubscriptionURI);

    ret = DPS_BufferInit(&payload, NULL, allocSize);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Write listening port
     */
    CBOR_EncodeUint16(&payload, node->port);
    CBOR_EncodeUint16(&payload, ttl);
    CBOR_EncodeBoolean(&payload, remote->inbound.sync);
    CBOR_EncodeBoolean(&payload, remote->outbound.sync);
    ret = DPS_BitVectorSerialize(needs, &payload);
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(interests, &payload);
    }
    if (ret == DPS_OK) {
        ret = CoAP_Compose(COAP_PROTOCOL, COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), DPS_BufferUsed(&payload), &headers);
    }
    if (ret == DPS_OK) {
        uv_buf_t bufs[] = {
            { (char*)headers.base, DPS_BufferUsed(&headers) },
            { (char*)payload.base, DPS_BufferUsed(&payload) }
        };
        ret = DPS_NetSend(node, &remote->ep, bufs, A_SIZEOF(bufs), OnNetSendComplete);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
            NetSendFailed(node, &remote->ep.addr, bufs, A_SIZEOF(bufs), ret);
        }
    } else {
        free(payload.base);
        return ret;
    }
    /*
     * Done with these flags
     */
    remote->inbound.sync = DPS_FALSE;
    remote->outbound.sync = DPS_FALSE;
    return ret;
}

/*
 * Unsubscribes this node from a remote node by sending a cleared bit vector
 */
static DPS_Status SendUnsubscribe(DPS_Node* node, RemoteNode* remote)
{
    if (remote->outbound.interests) {
        DPS_BitVectorClear(remote->outbound.interests);
        DPS_BitVectorClear(remote->outbound.needs);
    } else {
        remote->outbound.interests = DPS_BitVectorAlloc();
        remote->outbound.needs = DPS_BitVectorAllocFH();
        if (!remote->outbound.interests || !remote->outbound.needs) {
            DPS_BitVectorFree(remote->outbound.interests);
            DPS_BitVectorFree(remote->outbound.needs);
            return DPS_ERR_RESOURCES;
        }
    }
    remote->inbound.sync = DPS_FALSE;
    remote->outbound.sync = DPS_TRUE;
    return SendSubscription(node, remote, remote->outbound.interests, 0);
}

static void SendSubsTask(DPS_Node* node)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote;
    RemoteNode* remoteNext;

    DPS_DBGTRACE();

    /*
     * Forward subscription to all remote nodes with interestss
     */
    for (remote = node->remoteNodes; remote != NULL; remote = remoteNext) {
        DPS_BitVector* newInterests;

        remoteNext = remote->next;

        if (!remote->outbound.checkForUpdates) {
            continue;
        }
        remote->outbound.checkForUpdates = DPS_FALSE;
        if (uv_now(node->loop) >= remote->expires) {
            SendUnsubscribe(node, remote);
            DPS_DBGPRINT("Remote node has expired - deleting\n");
            DeleteRemoteNode(node, remote);
            continue;
        }
        ret = UpdateOutboundInterests(node, remote, &newInterests);
        if (ret != DPS_OK) {
            break;
        }
        if (newInterests) {
            ret = SendSubscription(node, remote, newInterests, UINT16_MAX);
            if (ret != DPS_OK) {
                DeleteRemoteNode(node, remote);
                DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
                ret = DPS_OK;
                continue;
            }
        }
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("SendSubsTask failed %s\n", DPS_ErrTxt(ret));
    }
}

static int SendSubs(DPS_Node* node, RemoteNode* remote)
{
    int count = 0;
    DPS_DBGTRACE();
    LockNode(node);
    if (node->remoteNodes) {
        if (remote) {
            remote->outbound.checkForUpdates = DPS_TRUE;
            ++count;
        } else {
            /*
             * TODO - when multi-tenancy is implemented subscriptions will only
             * be sent to remotes that match the tenancy criteria. For now we flood
             * subscriptions to all remote nodes.
             */
            for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
                remote->outbound.checkForUpdates = DPS_TRUE;
                ++count;
            }
        }
        if (count) {
            ScheduleBackgroundTask(node, SEND_SUBS_TASK);
        }
    }
    UnlockNode(node);
    return count;
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs, int delta)
{
    DPS_DBGTRACE();

    if (remote->inbound.interests) {
        if (delta) {
            DPS_DBGPRINT("Received interests delta\n");
            DPS_BitVectorXor(interests, interests, remote->inbound.interests, NULL);
        }
        DPS_CountVectorDel(node->interests, remote->inbound.interests);
        DPS_CountVectorDel(node->needs, remote->inbound.needs);
        DPS_BitVectorFree(remote->inbound.interests);
        remote->inbound.interests = NULL;
        DPS_BitVectorFree(remote->inbound.needs);
        remote->inbound.needs = NULL;
        remote->inbound.updates = DPS_TRUE;
    }
    if (DPS_BitVectorIsClear(interests)) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    } else {
        DPS_CountVectorAdd(node->interests, interests);
        DPS_CountVectorAdd(node->needs, needs);
        remote->inbound.interests = interests;
        remote->inbound.needs = needs;
        remote->inbound.updates = DPS_TRUE;
    }
    return DPS_OK;
}

/*
 *
 */
static DPS_Status DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    uint16_t port;
    uint16_t ttl;
    RemoteNode* remote;
    int syncRequested;
    int syncReceived;

    DPS_DBGTRACE();

    interests = DPS_BitVectorAlloc();
    if (!interests) {
        return DPS_ERR_RESOURCES;
    }
    needs = DPS_BitVectorAllocFH();
    if (!needs) {
        DPS_BitVectorFree(interests);
        return DPS_ERR_RESOURCES;
    }
    ret = CBOR_DecodeUint16(buffer, &port);
    if (ret != DPS_OK) {
        return ret;
    }
    EndpointSetPort(ep, port);
    ret = CBOR_DecodeUint16(buffer, &ttl);
    if (ret != DPS_OK) {
        return ret;
    }
    DPS_DBGPRINT("TTL=%d\n", ttl);
    ret = CBOR_DecodeBoolean(buffer, &syncRequested);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBoolean(buffer, &syncReceived);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_BitVectorDeserialize(needs, buffer);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_BitVectorDeserialize(interests, buffer);
    if (ret != DPS_OK) {
        return ret;
    }
    LockNode(node);
    ret = AddRemoteNode(node, &ep->addr, ep->cn, ttl, &remote);
    UnlockNode(node);
    if (ret != DPS_OK) {
        if (ret != DPS_ERR_EXISTS) {
            DPS_BitVectorFree(interests);
            DPS_BitVectorFree(needs);
            return ret;
        }
        ret = DPS_OK;
    } else {
        /*
         * The remote is new to us so we need to synchronize even if the remote
         * didn't request to.
         */
        syncRequested = DPS_TRUE;
    }
    LockNode(node);
    if (ttl == 0) {
        DeleteRemoteNode(node, remote);
    } else {
        if (syncRequested) {
            remote->outbound.sync = DPS_TRUE;
        }
        ret = UpdateInboundInterests(node, remote, interests, needs, !syncReceived);
        /*
         * Check if application waiting for a completion callback
         */
        if (remote->completion) {
            RemoteCompletion(node, remote, DPS_OK);
        }
    }
    UnlockNode(node);
    /*
     * Schedule background tasks
     */
    if (ret == DPS_OK) {
        SendPubs(node, NULL);
        SendSubs(node, NULL);
    }
    return ret;
}

static void DecodeRequest(DPS_Node* node, DPS_NetEndpoint* ep, CoAP_Parsed* coap, DPS_Buffer* payload, int multicast)
{
    DPS_Status ret;
    RequestType req = 0;
    size_t i;

    for (i = 0; i < coap->numOpts; ++i) {
        if (coap->opts[i].id == COAP_OPT_URI_PATH) {
            if (strncmp((char*)coap->opts[i].val, DPS_SubscriptionURI, coap->opts[i].len) == 0) {
                req = SUB_REQ;
                break;
            }
            if (strncmp((char*)coap->opts[i].val, DPS_PublicationURI, coap->opts[i].len) == 0) {
                req = PUB_REQ;
                break;
            }
            if (strncmp((char*)coap->opts[i].val, DPS_AcknowledgmentURI, coap->opts[i].len) == 0) {
                req = ACK_REQ;
                break;
            }
        }
    }
    if (!req) {
        DPS_DBGPRINT("CoAP packet is not for us\n");
        return;
    }
    switch (req) {
    case SUB_REQ:
        if (coap->code != COAP_CODE(COAP_REQUEST, COAP_GET)) {
            DPS_ERRPRINT("Expected a GET request\n");
            return;
        }
        ret = DecodeSubscription(node, ep, payload);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscription returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case PUB_REQ:
        if (coap->code != COAP_CODE(COAP_REQUEST, COAP_PUT)) {
            DPS_ERRPRINT("Expected a PUT request\n");
            return;
        }
        DPS_DBGPRINT("Received publication via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DecodePublication(node, ep, payload, multicast);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublication returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case ACK_REQ:
        if (coap->code != COAP_CODE(COAP_REQUEST, COAP_PUT)) {
            DPS_ERRPRINT("Expected a PUT request\n");
            return;
        }
        DPS_DBGPRINT("Received acknowledgment via %s\n", DPS_NodeAddrToString(&ep->addr));
        ret = DecodeAcknowledgment(node, ep, payload);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeAcknowledgment returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    default:
        break;
    }
}

/*
 * Using CoAP packetization for receiving multicast subscription requests
 */
static ssize_t OnMulticastReceive(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Status status, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    ssize_t ret;
    CoAP_Parsed coap;

    DPS_DBGTRACE();

    if (!data || !len) {
        return 0;
    }
    /*
     * Ignore input that comes in after the node has been stopped
     */
    if (node->stopped) {
        return 0;
    }
    ret = CoAP_Parse(COAP_OVER_UDP, data, len, &coap, &payload);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Discarding garbage multicast packet len=%zu\n", len);
        return 0;
    }
    /*
     * Multicast packets must be non-confirmable
     */
    if (coap.type != COAP_TYPE_NON_CONFIRMABLE) {
        DPS_ERRPRINT("Discarding packet within bad type=%d\n", coap.type);
        return 0;
    }
    DecodeRequest(node, ep, &coap, &payload, DPS_TRUE);
    CoAP_Free(&coap);
    return len;
}

static ssize_t OnNetReceive(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Status status, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    CoAP_Parsed coap;
    size_t pktLen;
    DPS_Status ret;
    int protocol = COAP_PROTOCOL;

    DPS_DBGTRACE();

    /*
     * Ignore input that comes in after the node has been stopped
     */
    if (node->stopped) {
        return 0;
    }
    /*
     * Delete the remote node if the received failed
     */
    if (status != DPS_OK) {
        RemoteNode* remote;
        LockNode(node);
        remote = LookupRemoteNode(node, &ep->addr);
        if (remote) {
            DeleteRemoteNode(node, remote);
        }
        UnlockNode(node);
        return -1;
    }
    ret = CoAP_GetPktLen(protocol, data, len, &pktLen);
    if (ret == DPS_OK) {
        if (len < pktLen) {
            /*
             * Need more data
             */
            return pktLen - len;
        }
        ret = CoAP_Parse(protocol, data, len, &coap, &payload);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CoAP_Parse failed: ret= %d\n", ret);
            return -1;
        }
    }
    if (ret == DPS_ERR_EOD) {
        /*
         * Not enough data to parse length
         */
        return 1;
    }
    DecodeRequest(node, ep, &coap, &payload, DPS_FALSE);
    CoAP_Free(&coap);
    return 0;
}

static void StopNode(DPS_Node* node)
{
    LockNode(node);

    /*
     * Indicates the node is no longer running
     */
    node->stopped = DPS_TRUE;
    /*
     * Stop receivng and close all global handle
     */
    if (node->mcastReceiver) {
        DPS_MulticastStopReceive(node->mcastReceiver);
        node->mcastReceiver = NULL;
    }
    if (node->mcastSender) {
        DPS_MulticastStopSend(node->mcastSender);
        node->mcastSender = NULL;
    }
    if (node->netCtx) {
        DPS_NetStop(node->netCtx);
        node->netCtx = NULL;
    }
    assert(!uv_is_closing((uv_handle_t*)&node->bgHandler));
    uv_close((uv_handle_t*)&node->bgHandler, NULL);
    /*
     * Delete remote nodes and shutdown any connections.
     */
    while (node->remoteNodes) {
        DeleteRemoteNode(node, node->remoteNodes);
    }
    /*
     * Run the event loop again to ensure that all cleanup is
     * completed
     */
    uv_run(node->loop, UV_RUN_DEFAULT);
    /*
     * Free data structures
     */
    while (node->subscriptions) {
        node->subscriptions = FreeSubscription(node->subscriptions);
    }
    while (node->publications) {
        node->publications = FreePublication(node, node->publications);
    }
    DPS_CountVectorFree(node->interests);
    DPS_CountVectorFree(node->needs);
    DPS_BitVectorFree(node->scratch.interests);
    DPS_BitVectorFree(node->scratch.needs);
    DPS_HistoryFree(&node->history);
    /*
     * Cleanup mutexes etc.
     */
    uv_mutex_destroy(&node->condMutex);
    uv_mutex_destroy(&node->history.lock);

    assert(!uv_loop_alive(node->loop));

    uv_loop_close(node->loop);
    free(node->loop);
    /*
     * If we got here before the application called DPS_DestroyNode() we cannot free the node now,
     * it will be freed when DPS_DestroyNode() is called.
     */
    if (node->onDestroyed) {
        UnlockNode(node);
        node->onDestroyed(node, node->onDestroyedData);
        uv_mutex_destroy(&node->nodeMutex);
        free(node);
    } else {
        UnlockNode(node);
    }
}

static void NodeRun(void* arg)
{
    int r;
    DPS_Node* node = (DPS_Node*)arg;
    uv_thread_t thisThread = node->thread;

    uv_run(node->loop, UV_RUN_DEFAULT);

    DPS_DBGPRINT("Stopping node\n");
    StopNode(node);

    DPS_DBGPRINT("Exiting node thread\n");

    /*
     * Note: this is not currently a libuv API and is implemented locally
     */
    r = uv_thread_detach(&thisThread);
    if (r) {
        DPS_ERRPRINT("Failed to detatch thread: %s\n", uv_err_name(r));
    }
}

DPS_Node* DPS_CreateNode(const char* separators)
{
    DPS_Node* node = calloc(1, sizeof(DPS_Node));

    if (!node) {
        return NULL;
    }
    /*
     * One time initilization required
     */
    if (DPS_InitUUID() != DPS_OK) {
        free(node);
        return NULL;
    }
    if (!separators) {
        separators = "/";
    }
    strncpy(node->separators, separators, sizeof(node->separators));
    return node;
}

DPS_Status DPS_SetNodeData(DPS_Node* node, void* data)
{
    if (node) {
        node->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetNodeData(const DPS_Node* node)
{
    return node ?  node->userData : NULL;
}

DPS_Status DPS_StartNode(DPS_Node* node, int mcast, int rxPort)
{
    DPS_Status ret = DPS_OK;
    int r;

    if (!node) {
        return DPS_ERR_NULL;
    }
    node->history.loop = node->loop = calloc(1, sizeof(uv_loop_t));
    if (!node->loop) {
        return DPS_ERR_RESOURCES;
    }
    r = uv_loop_init(node->loop);
    if (r) {
        free(node->loop);
        node->loop = NULL;
        node->history.loop = NULL;
        return DPS_ERR_FAILURE;
    }
    DPS_DBGPRINT("libuv version %s\n", uv_version_string());
    /*
     * For triggering background tasks
     */
    node->bgHandler.data = node;
    r = uv_async_init(node->loop, &node->bgHandler, RunBackgroundTasks);
    assert(!r);
    /*
     * Mutex for protecting the node
     */
    r = uv_mutex_init(&node->condMutex);
    assert(!r);
    r = uv_mutex_init(&node->nodeMutex);
    assert(!r);
    r = uv_mutex_init(&node->history.lock);
    assert(!r);

    node->interests = DPS_CountVectorAlloc();
    node->needs = DPS_CountVectorAllocFH();
    node->scratch.interests = DPS_BitVectorAlloc();
    node->scratch.needs = DPS_BitVectorAllocFH();

    if (!node->interests || !node->needs || !node->scratch.interests || !node->scratch.needs) {
        ret = DPS_ERR_RESOURCES;
        goto ErrExit;
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_RECV) {
        node->mcastReceiver = DPS_MulticastStartReceive(node, OnMulticastReceive);
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_SEND) {
        node->mcastSender = DPS_MulticastStartSend(node);
    }
    node->netCtx = DPS_NetStart(node, rxPort, OnNetReceive);
    if (!node->netCtx) {
        DPS_ERRPRINT("Failed to initialize network context on port %d\n", rxPort);
        ret = DPS_ERR_NETWORK;
        goto ErrExit;
    }
    /*
     * Make sure have the listenting port before we return
     */
    node->port = DPS_NetGetListenerPort(node->netCtx);
    assert(node->port);
    /*
     *  The node loop gets its own thread to run on
     */
    r = uv_thread_create(&node->thread, NodeRun, node);
    if (r) {
        DPS_ERRPRINT("Failed to create node thread\n");
        ret = DPS_ERR_FAILURE;
        goto ErrExit;
    }
    return DPS_OK;

ErrExit:

    StopNode(node);
    return ret;

}

DPS_NetContext* DPS_GetNetContext(DPS_Node* node)
{
    return node->netCtx;
}

uv_loop_t* DPS_GetLoop(DPS_Node* node)
{
    return node->loop;
}

uint16_t DPS_GetPortNumber(DPS_Node* node)
{
    if (node) {
        return node->port;
    } else {
        return 0;
    }

}

static void StopNodeTask(DPS_Node* node)
{
    DPS_DBGTRACE();
    uv_stop(node->loop);
}

DPS_Status DPS_DestroyNode(DPS_Node* node, DPS_OnNodeDestroyed cb, void* data)
{
    DPS_DBGTRACE();
    if (!node || !cb) {
        return DPS_ERR_NULL;
    }
    if (node->onDestroyed) {
        return DPS_ERR_INVALID;
    }
    if (!node->loop) {
        return DPS_OK;
    }
    LockNode(node);
    if (!node->stopped) {
        node->onDestroyed = cb;
        node->onDestroyedData = data;
        node->tasks |= STOP_NODE_TASK;
        uv_async_send(&node->bgHandler);
        UnlockNode(node);
        return DPS_OK;
    }
    UnlockNode(node);
    uv_mutex_destroy(&node->nodeMutex);
    free(node);
    return DPS_ERR_NODE_DESTROYED;
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
    DumpTopics(topics, numTopics);

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
        LockNode(node);
        pub->next = node->publications;
        node->publications = pub;
        UnlockNode(node);
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
    LockNode(node);
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
            UnlockNode(node);
            DPS_ERRPRINT("Negative ttl only valid for retained publications\n");
            return DPS_ERR_INVALID;
        }
        if (payload) {
            UnlockNode(node);
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
        UnlockNode(node);
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

    UnlockNode(node);
    SendPubs(node, pub);
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
    LockNode(node);
    if (payload) {
        *payload = (uint8_t*)pub->payload.base;
    }
    FreePublication(node, pub);
    UnlockNode(node);
    return DPS_OK;
}

DPS_Status DPS_Link(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnLinkComplete cb, void* data)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = NULL;

    DPS_DBGTRACE();
    if (!addr || !node || !cb) {
        return DPS_ERR_NULL;
    }
    LockNode(node);
    ret = AddRemoteNode(node, addr, NULL, REMOTE_NODE_KEEPALIVE, &remote);
    if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
        UnlockNode(node);
        return ret;
    }
    /*
     * Remote may already exist due to incoming data
     */
    if (remote->linked) {
        DPS_ERRPRINT("Node at %s already linked\n", DPS_NodeAddrToString(addr));
        UnlockNode(node);
        return ret;
    }
    /*
     * Operations must be serialized
     */
    if (remote->completion) {
        UnlockNode(node);
        return DPS_ERR_BUSY;
    }
    remote->linked = DPS_TRUE;
    remote->outbound.sync = DPS_TRUE;
    if (ret == DPS_OK) {
        remote->inbound.sync = DPS_TRUE;
    }
    remote->completion = AllocCompletion(node, remote, LINK_OP, data, LINK_RESPONSE_TIMEOUT, cb);
    if (!remote->completion) {
        DeleteRemoteNode(node, remote);
        UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    UnlockNode(node);
    SendSubs(node, remote);
    return DPS_OK;
}

DPS_Status DPS_Unlink(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnUnlinkComplete cb, void* data)
{
    RemoteNode* remote;

    DPS_DBGTRACE();
    if (!addr || !node || !cb) {
        return DPS_ERR_NULL;
    }
    LockNode(node);
    remote = LookupRemoteNode(node, addr);
    if (!remote || !remote->linked) {
        UnlockNode(node);
        return DPS_ERR_MISSING;
    }
    /*
     * Operations must be serialized
     */
    if (remote->completion) {
        UnlockNode(node);
        return DPS_ERR_BUSY;
    }
    /*
     * Expiring the remote node will cause it to be deleted after the
     * subscriptions are updated. When the remote node is removed
     * the completion callback will be called.
     */
    remote->expires = 0;
    remote->completion = AllocCompletion(node, remote, UNLINK_OP, data, LINK_RESPONSE_TIMEOUT, cb);
    if (!remote->completion) {
        DeleteRemoteNode(node, remote);
        UnlockNode(node);
        return DPS_ERR_RESOURCES;
    }
    UnlockNode(node);
    SendSubs(node, remote);
    return DPS_OK;
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
    return QueuePublicationAck(node, ack, payload, len, addr);
}

DPS_Subscription* DPS_CreateSubscription(DPS_Node* node, const char** topics, size_t numTopics)
{
    size_t i;
    DPS_Subscription* sub;

    if (!node || !topics || !numTopics) {
        return NULL;
    }
    sub = calloc(1, sizeof(DPS_Subscription) + sizeof(char*) * (numTopics - 1));
    /*
     * Add the topics to the subscription
     */
    for (i = 0; i < numTopics; ++i) {
        size_t len = strlen(topics[i]);
        sub->topics[i] = malloc(len + 1);
        if (!sub->topics[i]) {
            FreeSubscription(sub);
            return NULL;
        }
        ++sub->numTopics;
        memcpy(sub->topics[i], topics[i], len + 1);
    }
    sub->node = node;
    return sub;
}

DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler)
{
    size_t i;
    DPS_Status ret = DPS_OK;
    DPS_Node* node = sub ? sub->node : NULL;

    if (!node) {
        return DPS_ERR_NULL;
    }
    if (!node->loop) {
        return DPS_ERR_NOT_STARTED;
    }
    sub->handler = handler;
    sub->bf = DPS_BitVectorAlloc();
    sub->needs = DPS_BitVectorAllocFH();
    if (!sub->bf || !sub->needs) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Add the topics to the bloom filter
     */
    for (i = 0; i < sub->numTopics; ++i) {
        ret = DPS_AddTopic(sub->bf, sub->topics[i], node->separators, DPS_SubTopic);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        return ret;
    }

    DPS_DBGPRINT("Subscribing to %zu topics\n", sub->numTopics);
    DumpTopics((const char**)sub->topics, sub->numTopics);

    DPS_BitVectorFuzzyHash(sub->needs, sub->bf);
    /*
     * Protect the node while we update it
     */
    LockNode(node);
    sub->next = node->subscriptions;
    node->subscriptions = sub;
    ret = DPS_CountVectorAdd(node->interests, sub->bf);
    if (ret == DPS_OK) {
        ret = DPS_CountVectorAdd(node->needs, sub->needs);
    }
    UnlockNode(node);
    if (ret == DPS_OK) {
        SendSubs(node, NULL);
    }
    return ret;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_Node* node;

    if (!IsValidSub(sub)) {
        return DPS_ERR_MISSING;
    }
    node = sub->node;
    /*
     * Protect the node while we update it
     */
    LockNode(node);
    /*
     * Unlink the subscription
     */
    if (node->subscriptions == sub) {
        node->subscriptions = sub->next;
    } else {
        DPS_Subscription* prev = node->subscriptions;
        while (prev->next != sub) {
            prev = prev->next;
        }
        prev->next = sub->next;
    }
    /*
     * This remove this subscriptions contributions to the interests and needs
     */
    if (DPS_CountVectorDel(node->interests, sub->bf) != DPS_OK) {
        assert(!"Count error");
    }
    if (DPS_CountVectorDel(node->needs, sub->needs) != DPS_OK) {
        assert(!"Count error");
    }
    UnlockNode(node);

    DPS_DBGPRINT("Unsubscribing from %zu topics\n", sub->numTopics);
    DumpTopics((const char**)sub->topics, sub->numTopics);
    FreeSubscription(sub);

    SendSubs(node, NULL);

    return DPS_OK;
}

static void RunBackgroundTasks(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    DPS_DBGTRACE();

    /*
     * TODO - may need to break some tasks into subtasks,
     * for example limit the number of subs or pubs on each
     * iteration so the node lock doesn't get held for too long.
     */
    LockNode(node);
    /*
     * The tasks are ordered according to priority
     */
    if (node->tasks & SEND_ACKS_TASK) {
        node->tasks &= ~SEND_ACKS_TASK;
        SendAcksTask(node);
    } else if (node->tasks & SEND_PUBS_TASK) {
        node->tasks &= ~SEND_PUBS_TASK;
        SendPubsTask(node);
    } else if (node->tasks & SEND_SUBS_TASK) {
        node->tasks &= ~SEND_SUBS_TASK;
        SendSubsTask(node);
    } else if (node->tasks & STOP_NODE_TASK) {
        node->tasks &= ~STOP_NODE_TASK;
        StopNodeTask(node);
    }
    if (node->tasks) {
        uv_async_send(&node->bgHandler);
    }
    UnlockNode(node);
}

const char* DPS_NodeAddrToString(DPS_NodeAddress* addr)
{
    return DPS_NetAddrText((struct sockaddr*)&addr->inaddr);
}

DPS_NodeAddress* DPS_CreateAddress()
{
    return calloc(1, sizeof(DPS_NodeAddress));
}

void DPS_CopyAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src)
{
    if (dest && src) {
        *dest = *src;
    }
}

void DPS_DestroyAddress(DPS_NodeAddress* addr)
{
    if (addr) {
        free(addr);
    }
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

DPS_Status DPS_SetSubscriptionData(DPS_Subscription* sub, void* data)
{
    if (sub) {
        sub->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetSubscriptionData(DPS_Subscription* sub)
{
    return sub ? sub->userData : NULL;
}

void DPS_DumpSubscriptions(DPS_Node* node)
{
    DPS_Subscription* sub;

    DPS_DBGPRINT("Current subscriptions:\n");
    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        DumpTopics((const char**)sub->topics, sub->numTopics);
    }
}
