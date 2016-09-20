#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <uv.h>
#include <dps/dps_dbg.h>
#include <dps/bitvec.h>
#include <dps/topics.h>
#include <dps/dps.h>
#include <dps/dps_uuid.h>
#include <dps/coap.h>
#include <dps/cbor.h>
#include <dps/network.h>
#include <dps/dps_history.h>
#include <dps/dps_internal.h>
#include "dps_node.h"

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
#define PUB_FLAG_RETAINED (0x04) /* A received publication had a non-zero TTL */
#define PUB_FLAG_HISTORY  (0x08) /* A history record has been added for this publication */
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
    int16_t ttl;                    /* Remaining time-to-live in seconds */
    uint32_t sequenceNum;          /* Serial number for this publication */
    uint8_t* payload;
    size_t len;
    DPS_AcknowledgementHandler handler;
    DPS_UUID pubId;                 /* Publication identifier */
    DPS_NodeAddress sender;         /* for retained messages - the sender address */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Node* node;                 /* Node for this publication */
    DPS_Publication* next;
} DPS_Publication;

#define SEND_SUBS_TASK  0x01
#define SEND_PUBS_TASK  0x02
#define SEND_ACKS_TASK  0x04
#define STOP_NODE_TASK  0x08
#define FIND_ADDR_TASK  0x10

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
static void DumpTopics(char* const* topics, size_t numTopics)
{
    if (DPS_Debug) {
        size_t i;
        DPS_PRINT("     ");
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" & ");
            }
            DPS_PRINT("%s", topics[i]);
        }
        DPS_PRINT("\n");
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
            DPS_PRINT("  %s(%d) %s ttl=%d\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum, pub->flags & PUB_FLAG_RETAINED ? "RETAINED" : "", pub->ttl);
        }
    }
}
#endif

#define SameUUID(u1, u2)  (memcmp((u1), (u2), sizeof(DPS_UUID)) == 0)

#define NodeAddressText(a)        DPS_NetAddrText((struct sockaddr*)(&(a)->inaddr))
#define RemoteNodeAddressText(n)  NodeAddressText(&(n)->addr)


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

static void AddrSetPort(DPS_NodeAddress* dest, const struct sockaddr* addr, uint16_t port)
{
    port = htons(port);
    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)&dest->inaddr;
        memcpy(ip6, addr, sizeof(*ip6));
        ip6->sin6_port = port;
    } else {
        struct sockaddr_in* ip4 = (struct sockaddr_in*)&dest->inaddr;
        memcpy(ip4, addr, sizeof(*ip4));
        ip4->sin_port = port;
    }
}

static const uint8_t IP4as6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

static int SameAddr(DPS_NodeAddress* addr, const struct sockaddr* b)
{
    struct sockaddr* a = (struct sockaddr*)&addr->inaddr;
    struct sockaddr_in6 tmp;

    if (a->sa_family != b->sa_family) {
        uint32_t ip;
        if (a->sa_family == AF_INET6) {
            struct sockaddr_in* ipb = (struct sockaddr_in*)b;
            ip = ipb->sin_addr.s_addr;
            tmp.sin6_port = ipb->sin_port;
            b = (struct sockaddr*)&tmp;
        } else {
            struct sockaddr_in* ipa = (struct sockaddr_in*)a;
            ip = ipa->sin_addr.s_addr;
            tmp.sin6_port = ipa->sin_port;
            a = (struct sockaddr*)&tmp;
        }
        memcpy(&tmp.sin6_addr, IP4as6, 12);
        memcpy((uint8_t*)&tmp.sin6_addr + 12, &ip, 4);
        tmp.sin6_family = AF_INET6;
    }
    if (a->sa_family == AF_INET6) {
        struct sockaddr_in6* ip6a = (struct sockaddr_in6*)a;
        struct sockaddr_in6* ip6b = (struct sockaddr_in6*)b;
        return (ip6a->sin6_port == ip6b->sin6_port) && (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
    } else {
        struct sockaddr_in* ipa = (struct sockaddr_in*)a;
        struct sockaddr_in* ipb = (struct sockaddr_in*)b;
        return (ipa->sin_port == ipb->sin_port) && (ipa->sin_addr.s_addr == ipb->sin_addr.s_addr);
    }
}

DPS_Status DPS_BufferInit(DPS_Buffer* buffer, uint8_t* storage, size_t size)
{
    if (!storage) {
        storage = malloc(size);
        if (!storage) {
            return DPS_ERR_RESOURCES;
        }
    }
    buffer->base = storage;
    buffer->pos = storage;
    buffer->eod = storage + size;
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

static void RemoteCompletion(DPS_Node* node, RemoteNode* remote, DPS_Status status)
{
    OnOpCompletion* cpn = remote->completion;
    DPS_NodeAddress addr = remote->addr;

    remote->completion = NULL;
    UnlockNode(node);
    /*
     * TODO - make callback from an asynch
     */
    if (cpn->op == LINK_OP) {
        cpn->on.link(node, &addr, status, cpn->data);
    } else if (cpn->op == UNLINK_OP) {
        cpn->on.unlink(node, &addr, cpn->data);
    }
    LockNode(node);
    free(cpn);
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
    if (pub->payload && !(pub->flags & PUB_FLAG_LOCAL)) {
        free(pub->payload);
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
     * Don't compute the delta if we are sycnronizing outbound interests
     */
    if (destNode->outbound.sync) {
        DPS_BitVectorFree(destNode->outbound.interests);
        destNode->outbound.interests = NULL;
    }
    if (destNode->outbound.interests) {
        int same;
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

static RemoteNode* LookupRemoteNode(DPS_Node* node, const struct sockaddr* addr)
{
    RemoteNode* remote;

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        if (SameAddr(&remote->addr, addr)) {
            return remote;
        }
    }
    return NULL;
}

static OnOpCompletion* AllocCompletion(DPS_Node* node, OpType op, void* data, uint16_t ttl, void* cb)
{
    OnOpCompletion* cpn;

    cpn = calloc(1, sizeof(OnOpCompletion));
    if (cpn) {
        cpn->op = op;
        cpn->data = data;
        cpn->on.cb = cb;
        cpn->timeout = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    }
    return cpn;
}

/*
 * Add a remote node or return an existing one
 */
static DPS_Status AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, uint16_t ttl, RemoteNode** remoteOut)
{
    RemoteNode* remote = LookupRemoteNode(node, (struct sockaddr*)&addr->inaddr);
    if (remote) {
        *remoteOut = remote;
        remote->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
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
    DPS_DBGPRINT("Adding new remote node %s\n", NodeAddressText(addr));
    remote->addr.inaddr = addr->inaddr;
    remote->next = node->remoteNodes;
    remote->expires = uv_now(node->loop) + DPS_SECS_TO_MS(ttl);
    node->remoteNodes = remote;
    *remoteOut = remote;
    return DPS_OK;
}

static uint32_t UpdateTTLBasis(DPS_Node* node)
{
    uint64_t now = uv_now(node->loop);
    uint32_t elapsedSeconds = DPS_MS_TO_SECS(now - node->ttlBasis);
    node->ttlBasis = now;
    return elapsedSeconds;
}

static void CheckTTLs(DPS_Node* node)
{
    DPS_Publication* pub;
    DPS_Publication* next;
    uint32_t elapsed;
    size_t numTTLs = 0;

    if (!node->ttlBasis) {
        return;
    }
    elapsed = UpdateTTLBasis(node);
    if (!elapsed) {
        /*
         * Granularity is 1 second so this can happen
         */
        return;
    }
    for (pub = node->publications; pub != NULL; pub = next) {
        /*
         * In case this publication is freed below
         */
        next = pub->next;
        if ((pub->ttl > 0) && ((uint32_t)pub->ttl > elapsed)) {
            pub->ttl -= elapsed;
            ++numTTLs;
            continue;
        }
        /*
         * When a ttl expires retained publications are freed, local
         * publications are disabled by clearing the PUBLISH flag.
         */
        if (pub->flags & PUB_FLAG_LOCAL) {
            pub->flags &= ~PUB_FLAG_PUBLISH;
        } else if (pub->flags & PUB_FLAG_RETAINED) {
            DPS_DBGPRINT("Expiring retained pub %s\n", DPS_UUIDToString(&pub->pubId));
            FreePublication(node, pub);
        }
    }
    /*
     * If there are no TTLs to check clear the ttlBasis
     */
    if (numTTLs == 0) {
        node->ttlBasis = 0;
    }
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

static void NetSendFailed(DPS_Node* node, struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    RemoteNode* remote;

    DPS_ERRPRINT("NetSend failed %s\n", DPS_ErrTxt(status));
    remote = LookupRemoteNode(node, addr);
    if (remote) {
        DeleteRemoteNode(node, remote);
        DPS_ERRPRINT("Removed node %s\n", DPS_NetAddrText(addr));
    }
    FreeBufs(bufs, numBufs);
}

static void OnNetSendComplete(DPS_Node* node, struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        RemoteNode* remote;

        LockNode(node);
        remote = LookupRemoteNode(node, addr);
        DPS_ERRPRINT("OnNetSendComplete %s\n", DPS_ErrTxt(status));
        if (remote) {
            DeleteRemoteNode(node, remote);
            DPS_ERRPRINT("Removed node %s\n", DPS_NetAddrText(addr));
        }
        UnlockNode(node);
    }
    FreeBufs(bufs, numBufs);
}

/*
 * Add this publication to the history record
 */
static DPS_Status UpdatePubHistory(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Status ret = DPS_OK;
    if (!(pub->flags & PUB_FLAG_HISTORY)) {
        ret = DPS_UpdatePubHistory(&node->history, &pub->pubId, pub->sequenceNum, pub->ttl, pub->ackRequested ? &pub->sender : NULL);
        pub->flags |= PUB_FLAG_HISTORY;
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
static DPS_Status SendPublication(DPS_Node* node, DPS_Publication* pub, DPS_BitVector* bf, RemoteNode* remote)
{
    DPS_Status ret;
    DPS_Buffer payload;
    uv_buf_t bufs[3];
    CoAP_Option opts[1];
    int protocol;

    DPS_DBGTRACE();

    if (remote) {
        DPS_DBGPRINT("SendPublication (ttl=%d) to %s\n", pub->ttl, RemoteNodeAddressText(remote));
        protocol = COAP_PROTOCOL;
    } else {
        DPS_DBGPRINT("SendPublication (ttl=%d) as multicast\n", pub->ttl);
        protocol = COAP_OVER_UDP;
    }
    ret = DPS_BufferInit(&payload, NULL, 32 + DPS_BitVectorSerializeMaxSize(bf) + pub->len);
    if (ret != DPS_OK) {
        return DPS_OK;
    }
    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_PublicationURI;
    opts[0].len = sizeof(DPS_PublicationURI);
    /*
     * Write the listening port, ttl, pubId, and serial number
     */
    CBOR_EncodeUint16(&payload, node->port);
    CBOR_EncodeInt16(&payload, pub->ttl);
    CBOR_EncodeBytes(&payload, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    CBOR_EncodeUint(&payload, pub->sequenceNum);
    CBOR_EncodeBoolean(&payload, pub->ackRequested);

    ret = DPS_BitVectorSerialize(bf, &payload);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, pub->payload, pub->len);
        ret = CoAP_Compose(protocol, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
    }
    if (ret == DPS_OK) {
        if (remote) {
            ret = DPS_NetSend(node->netCtx, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr.inaddr, OnNetSendComplete);
            if (ret == DPS_OK) {
                UpdatePubHistory(node, pub);
            } else {
                NetSendFailed(node, (struct sockaddr*)&remote->addr.inaddr, bufs, A_SIZEOF(bufs), ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs));
            FreeBufs(bufs, A_SIZEOF(bufs));
        }
    } else {
        free(payload.base);
    }
    return ret;
}

static DPS_BitVector* PubSubMatch(DPS_Node* node, DPS_Publication* pub, RemoteNode* sub)
{
    DPS_BitVectorIntersection(node->scratch.interests, pub->bf, sub->inbound.interests);
    DPS_BitVectorFuzzyHash(node->scratch.needs, node->scratch.interests);
    if (DPS_BitVectorIncludes(node->scratch.needs, sub->inbound.needs)) {
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

static DPS_Status SendMatchingPubToSub(DPS_Node* node, DPS_Publication* pub, RemoteNode* sub)
{
    /*
     * We don't send publications back to the remote node than sent them
     */
    if (!SameAddr(&pub->sender, (struct sockaddr*)&sub->addr)) {
        DPS_BitVector* pubBV = PubSubMatch(node, pub, sub);
        if (pubBV) {
            DPS_DBGPRINT("Sending pub %d to %s\n", pub->sequenceNum, RemoteNodeAddressText(sub));
            return SendPublication(node, pub, pubBV, sub);
        }
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->sequenceNum, RemoteNodeAddressText(sub));
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
    DPS_Buffer payload;
    size_t allocSize = 8 + sizeof(DPS_UUID) + sizeof(uint32_t) + len;

    DPS_DBGTRACE();

    assert(ack->sequenceNum != 0);

    if (!node->netCtx) {
        return DPS_ERR_NETWORK;
    }

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_AcknowledgmentURI;
    opts[0].len = sizeof(DPS_AcknowledgmentURI);

    ret = DPS_BufferInit(&payload, NULL, allocSize);
    if (ret != DPS_OK) {
        free(ack);
        return ret;
    }
    CBOR_EncodeBytes(&payload, (uint8_t*)&ack->pubId, sizeof(DPS_UUID));
    CBOR_EncodeUint32(&payload, ack->sequenceNum);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, data, len);
        ret = CoAP_Compose(COAP_PROTOCOL, ack->bufs, A_SIZEOF(ack->bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
        if (ret != DPS_OK) {
            free(payload.base);
            free(ack);
        } else {
            LockNode(node);
            ack->destAddr = *destAddr;
            ack->next = node->ackQueue.last;
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

static DPS_Status DecodeAcknowledgment(DPS_Node* node, DPS_Buffer* buffer)
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
            DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), sequenceNum, NodeAddressText(addr));
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
        DPS_Status ret = DPS_NetSend(node->netCtx, ack->bufs, A_SIZEOF(ack->bufs), (struct sockaddr*)&ack->destAddr.inaddr, OnNetSendComplete);
        if (ret != DPS_OK) {
            NetSendFailed(node, (struct sockaddr*)&ack->destAddr.inaddr, ack->bufs, A_SIZEOF(ack->bufs), ret);
        }
        node->ackQueue.first = ack->next;
        free(ack);
    }
    node->ackQueue.last = NULL;
}

static void SendPubsTask(DPS_Node* node)
{
    DPS_Status ret;
    DPS_Publication* pub;
    DPS_Publication* nextPub;

    DPS_DBGTRACE();

    /*
     * Removed any stale retained pubs
     */
    CheckTTLs(node);
    /*
     * Check if any local or retained publications need to be forwarded to this subscriber
     */
    for (pub = node->publications; pub != NULL; pub = nextPub) {
        RemoteNode* remote;
        RemoteNode* nextRemote;

        nextPub = pub->next;
        /*
         * If the node is a multicast sender local publications are always multicast
         */
        if (node->mcastSender && (pub->flags & PUB_FLAG_LOCAL) && (pub->flags & PUB_FLAG_PUBLISH)) {
            DPS_Status ret = SendPublication(node, pub, pub->bf, NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("SendPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
            }
        }
        /*
         * Only check publications that are flagged to be checked
         */
        if (pub->checkToSend) {
            pub->checkToSend = DPS_FALSE;
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
        }
        /*
         * Check if the publication has expired
         */
        if (pub->ttl <= 0) {
            if (pub->flags & PUB_FLAG_LOCAL) {
                pub->flags &= ~PUB_FLAG_PUBLISH;
                DPS_DBGPRINT("Disabling local pub %s\n", DPS_UUIDToString(&pub->pubId));
            } else {
                DPS_DBGPRINT("Deleting pub %s\n", DPS_UUIDToString(&pub->pubId));
                FreePublication(node, pub);
            }
        }
    }
    /*
     * If there are no other retained pubs the ttlBasis time will not be set
     */
    if (!node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    DumpPubs(node);
}

/*
 * Run checks of one or more publications against the current subscriptions
 */
static int SendPubs(DPS_Node* node, DPS_Publication* pub)
{
    int count = 0;
    LockNode(node);

    /*
     * Need something to send and somwhere to send it
     */
    if (node->publications && (node->remoteNodes || node->mcastSender)) {
        if (pub) {
            if (pub->flags & PUB_FLAG_PUBLISH) {
                pub->checkToSend = DPS_TRUE;
                ++count;
            }
        } else {
            /*
             * Check all publications
             */
            for (pub = node->publications; pub != NULL; pub = pub->next) {
                if (pub->flags & PUB_FLAG_PUBLISH) {
                    pub->checkToSend = DPS_TRUE;
                    ++count;
                }
            }
        }
        if (count) {
            ScheduleBackgroundTask(node, SEND_PUBS_TASK);
        }
    }
    UnlockNode(node);
    return count;
}

/*
 * Check if there is a local subscription for this publication
 * Note that we don't deliver expired publications to the handler.
 */
static void CallPubHandlers(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Subscription* sub;
    DPS_Subscription* next;

    DPS_DBGTRACE();

    LockNode(node);
    for (sub = node->subscriptions; sub != NULL; sub = next) {
        /*
         * Ths current subscription might get freed by the handler so need to hold the next pointer here.
         */
        next = sub->next;
        if (DPS_BitVectorIncludes(pub->bf, sub->bf)) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            /*
             * TODO - make callback from any async
             */
            UnlockNode(node);
            sub->handler(sub, pub, pub->payload, pub->len);
            LockNode(node);
        }
    }
    UnlockNode(node);
}

static DPS_Status DecodePublication(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr, int multicast)
{
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_Publication* pub = NULL;
    DPS_UUID* pubId;
    uint32_t sequenceNum;
    int16_t ttl;
    uint8_t* payload;
    int ackRequested;
    size_t len;

    DPS_DBGTRACE();

    ret = CBOR_DecodeUint16(buffer, &port);
    if (ret != DPS_OK) {
        goto Exit;
    }
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
    if (DPS_PublicationIsStale(&node->history, pubId, sequenceNum)) {
        DPS_DBGPRINT("Publication is stale\n");
        return DPS_OK;
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
    pub->ttl = ttl;
    pub->sequenceNum = sequenceNum;
    pub->ackRequested = ackRequested;
    pub->flags = PUB_FLAG_PUBLISH;
    AddrSetPort(&pub->sender, addr, port);
    /*
     * We have no reason to hold onto a node for multicast publishers
     */
    if (!multicast) {
        LockNode(node);
        ret = AddRemoteNode(node, &pub->sender, UINT16_MAX, &pubNode);
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
    if (pub->ttl < 0) {
        if (pub->payload) {
            free(pub->payload);
        }
        pub->len = 0;
    } else {
        /*
         * Payload is a pointer into the receive buffer so must be copied
         */
        ret = CBOR_DecodeBytes(buffer, &payload, &len);
        if (ret != DPS_OK) {
            goto Exit;
        }
        if (len) {
            pub->payload = realloc(pub->payload, len);
            if (!pub->payload) {
                goto Exit;
            }
            memcpy(pub->payload, payload, len);
        } else if (pub->payload) {
            free(pub->payload);
            pub->payload = NULL;
        }
        pub->len = len;
        if (pub->ttl > 0) {
            pub->flags |= PUB_FLAG_RETAINED;
        }
        /*
         * Forward the publication to matching local subscribers
         */
        CallPubHandlers(node, pub);
    }
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
        FreePublication(node, pub);
        UnlockNode(node);
    }
    return ret;
}

static DPS_Status SendSubscription(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, uint16_t ttl)
{
    uv_buf_t bufs[3];
    DPS_Status ret;
    CoAP_Option opts[1];
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
        ret = CoAP_Compose(COAP_PROTOCOL, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), &payload);
    }
    if (ret != DPS_OK) {
        free(payload.base);
        return ret;
    }
    ret = DPS_NetSend(node->netCtx, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr.inaddr, OnNetSendComplete);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
        NetSendFailed(node, (struct sockaddr*)&remote->addr, bufs, A_SIZEOF(bufs), ret);
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
    uint64_t now = uv_now(node->loop);

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
        if (now >= remote->expires) {
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
static DPS_Status DecodeSubscription(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr)
{
    DPS_Status ret;
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    DPS_NodeAddress senderAddr;
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
    AddrSetPort(&senderAddr, addr, port);
    LockNode(node);
    ret = AddRemoteNode(node, &senderAddr, ttl, &remote);
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

static void DecodeRequest(DPS_Node* node, CoAP_Parsed* coap, DPS_Buffer* payload, const struct sockaddr* sender, int multicast)
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
        ret = DecodeSubscription(node, payload, sender);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscription returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case PUB_REQ:
        if (coap->code != COAP_CODE(COAP_REQUEST, COAP_PUT)) {
            DPS_ERRPRINT("Expected a PUT request\n");
            return;
        }
        DPS_DBGPRINT("Received publication via %s\n", DPS_NetAddrText(sender));
        ret = DecodePublication(node, payload, sender, multicast);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublication returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case ACK_REQ:
        if (coap->code != COAP_CODE(COAP_REQUEST, COAP_PUT)) {
            DPS_ERRPRINT("Expected a PUT request\n");
            return;
        }
        DPS_DBGPRINT("Received acknowledgment via %s\n", DPS_NetAddrText(sender));
        ret = DecodeAcknowledgment(node, payload);
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
static ssize_t OnMulticastReceive(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    ssize_t ret;
    CoAP_Parsed coap;

    DPS_DBGTRACE();

    if (!data || !len) {
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
    DecodeRequest(node, &coap, &payload, addr, DPS_TRUE);
    CoAP_Free(&coap);
    return len;
}

static ssize_t OnNetReceive(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    CoAP_Parsed coap;
    size_t pktLen;
    DPS_Status ret;

    DPS_DBGTRACE();

    ret = CoAP_GetPktLen(COAP_PROTOCOL, data, len, &pktLen);
    if (ret == DPS_OK) {
        if (len < pktLen) {
            /*
             * Need more data
             */
            return pktLen - len;
        }
        ret = CoAP_Parse(COAP_PROTOCOL, data, len, &coap, &payload);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CoAP_Parse failed: ret= %d\n", ret);
            return -(ssize_t)len;
        }
    }
    if (ret == DPS_ERR_EOD) {
        /*
         * Not enough data to parse length
         */
        return 1;
    }
    DecodeRequest(node, &coap, &payload, addr, DPS_FALSE);
    CoAP_Free(&coap);
    return 0;
}

static void StopNode(DPS_Node* node)
{
    /*
     * Close all the handles and...
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
    assert(!uv_is_closing((uv_handle_t*)&node->shutdownTimer));
    uv_close((uv_handle_t*)&node->shutdownTimer, NULL);
    /*
     * ...run the event loop again to ensure that all cleanup is
     * completed
     */
    uv_run(node->loop, UV_RUN_DEFAULT);
}

static void DestroyNode(DPS_Node* node)
{
    while (node->remoteNodes) {
        DeleteRemoteNode(node, node->remoteNodes);
    }
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

    uv_mutex_destroy(&node->nodeMutex);
    uv_mutex_destroy(&node->condMutex);
    uv_mutex_destroy(&node->history.lock);

    assert(!uv_loop_alive(node->loop));

    uv_loop_close(node->loop);
    free(node->loop);
    free(node);
}

static void NodeRun(void* arg)
{
    DPS_Node* node = (DPS_Node*)arg;

    uv_run(node->loop, UV_RUN_DEFAULT);

    DPS_DBGPRINT("Exiting node thread\n");
    StopNode(node);
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
    int r;

    if (!node) {
        return DPS_ERR_NULL;
    }
    node->history.loop = node->loop = calloc(1, sizeof(uv_loop_t));
    if (!node->loop) {
        free(node);
        return DPS_ERR_RESOURCES;
    }
    r = uv_loop_init(node->loop);
    if (r) {
        return DPS_ERR_FAILURE;
    }
    DPS_DBGPRINT("libuv version %s\n", uv_version_string());
    /*
     * Timer for clean shutdown
     */
    node->shutdownTimer.data = node;
    uv_timer_init(node->loop, &node->shutdownTimer);
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
        return DPS_ERR_RESOURCES;
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
        return DPS_ERR_NETWORK;
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
        return DPS_ERR_FAILURE;
    }
    return DPS_OK;
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

#define STOP_TIMEOUT 200

static void StopOnTimeout(uv_timer_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_DBGTRACE();
    uv_stop(node->loop);
}

static void StopNodeTask(DPS_Node* node)
{
    DPS_DBGTRACE();
    uv_timer_start(&node->shutdownTimer, StopOnTimeout, STOP_TIMEOUT, 0);
}

void DPS_StopNode(DPS_Node* node)
{
    DPS_DBGTRACE();
    LockNode(node);
    ScheduleBackgroundTask(node, STOP_NODE_TASK);
    UnlockNode(node);
}

void DPS_DestroyNode(DPS_Node* node)
{
    if (uv_thread_join(&node->thread) == 0) {
        DestroyNode(node);
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

DPS_Status DPS_InitPublication(DPS_Publication* pub, char* const* topics, size_t numTopics, DPS_AcknowledgementHandler handler)
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
    if ((pub->flags & PUB_FLAG_IS_COPY) || pub->bf) {
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

    for (i = 0; i < numTopics; ++i) {
        ret = DPS_AddTopic(pub->bf, topics[i], node->separators, DPS_Pub);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret == DPS_OK) {
        LockNode(node);
        pub->next = node->publications;
        node->publications = pub;
        UnlockNode(node);
    }
    return ret;
}

DPS_Status DPS_Publish(DPS_Publication* pub, uint8_t* payload, size_t len, int16_t ttl, uint8_t** oldPayload)
{
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
        *oldPayload = pub->payload;
    }
    pub->payload = payload;
    pub->len = len;
    pub->flags |= PUB_FLAG_PUBLISH;
    pub->ttl = ttl >= 0 ? ttl : -1;
    ++pub->sequenceNum;

    if ((pub->ttl > 0) && !node->ttlBasis) {
        UpdateTTLBasis(node);
    }
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
        *payload = pub->payload;
    }
    FreePublication(node, pub);
    UnlockNode(node);
    return DPS_OK;
}

#define LINK_TTL  5

DPS_Status DPS_Link(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnLinkComplete cb, void* data)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = NULL;
    uint16_t ttl = UINT16_MAX;

    DPS_DBGTRACE();
    if (!addr || !node || !cb) {
        return DPS_ERR_NULL;
    }
    LockNode(node);
    ret = AddRemoteNode(node, addr, ttl, &remote);
    if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
        UnlockNode(node);
        return ret;
    }
    /*
     * Remote may already exist due to incoming data
     */
    if (remote->linked) {
        DPS_ERRPRINT("Node at %s already linked\n", NodeAddressText(addr));
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
    remote->completion = AllocCompletion(node, LINK_OP, data, LINK_TTL, cb);
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
    remote = LookupRemoteNode(node, (struct sockaddr*)&addr->inaddr);
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
    remote->expires = uv_now(node->loop);
    remote->completion = AllocCompletion(node, UNLINK_OP, data, LINK_TTL, cb);
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
    DPS_DBGPRINT("Queueing acknowledgement for %s/%d to %s\n", DPS_UUIDToString(&pub->pubId), pub->sequenceNum, NodeAddressText(addr));
    ack = AllocPubAck(&pub->pubId, pub->sequenceNum);
    if (!ack) {
        return DPS_ERR_RESOURCES;
    }
    return QueuePublicationAck(node, ack, payload, len, addr);
}

DPS_Subscription* DPS_CreateSubscription(DPS_Node* node, char* const* topics, size_t numTopics)
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
        ret = DPS_AddTopic(sub->bf, sub->topics[i], node->separators, DPS_Sub);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        return ret;
    }

    DPS_DBGPRINT("Subscribing to %zu topics\n", sub->numTopics);
    DumpTopics(sub->topics, sub->numTopics);

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
    DumpTopics(sub->topics, sub->numTopics);
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

const char* DPS_GetAddressText(DPS_NodeAddress* addr)
{
    return NodeAddressText(addr);
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
        DumpTopics(sub->topics, sub->numTopics);
    }
}
