#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <uv.h>
#include <dps_dbg.h>
#include <bitvec.h>
#include <topics.h>
#include <dps.h>
#include <dps_uuid.h>
#include <coap.h>
#include <cbor.h>
#include <network.h>
#include "dps_history.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#define _MIN_(x, y)  (((x) < (y)) ? (x) : (y))


static const char DPS_SubscriptionURI[] = "dps/sub";
static const char DPS_PublicationURI[] = "dps/pub";
static const char DPS_AcknowledgmentURI[] = "dps/ack";

typedef enum { NO_REQ, SUB_REQ, PUB_REQ, ACK_REQ } RequestType;

#define REQUIRE_BASELINE_INTERESTS      0x01  /* Baseline interests are needed from this remote */
#define SENDING_BASELINE_INTERESTS      0x02  /* Baseline interests must be sent to this remote */

typedef struct _RemoteNode {
    uint8_t flags;                     /* bitwise OR of the flags above */
    uint8_t joined;                    /* True if this is a node that was explicitly joined */
    DPS_NodeAddress addr;
    struct {
        uint8_t updates;               /* TRUE if updates have been received but not acted on */
        DPS_BitVector* needs;          /* Bit vector of needs received from  this remote node */
        DPS_BitVector* interests;      /* Bit vector of interests received from  this remote node */
    } inbound;
    struct {
        uint8_t checkForUpdates;       /* TRUE if there may be updated interests to send to this remote */
        DPS_BitVector* needs;          /* Needs bit vector sent outbound to this remote node */
        DPS_BitVector* interests;      /* Interests bit vector sent outbound to this remote node */
    } outbound;
    struct _RemoteNode* next;
} RemoteNode;

/*
 * Struct to hold the state of a local subscription. We hold the topics so we can provide return the topic list when we
 * get a match. We compute the filter so we can forward to outbound subscribers.
 */
typedef struct _DPS_Subscription {
    DPS_BitVector* needs;           /* Subscription needs */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this subscription */
    DPS_PublicationHandler handler; /* Callback function to be called for a matching publication */
    DPS_Subscription* next;
    size_t numTopics;               /* Number of subscription topics */
    char* topics[1];                /* Subscription topics */
} DPS_Subscription;


#define PUB_FLAG_PUBLISH  (0x01) /* The publication should be published */
#define PUB_FLAG_LOCAL    (0x02) /* The publication is local to this node */
#define PUB_FLAG_RETAINED (0x04) /* A received publication had a non-zero TTL */
#define PUB_FLAG_HISTORY  (0x08) /* A history record has been added for this publication */

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
    uint8_t flags;                  /* Internal state flags */
    uint8_t checkToSend;            /* TRUE if this publication should be checked to send */
    uint8_t ackRequested;           /* TRUE if an ack was requested by the publisher */
    int16_t ttl;                    /* Remaining time-to-live in seconds */
    uint32_t serialNumber;          /* Serial number for this publication */
    uint8_t* payload;
    size_t len;
    DPS_AcknowledgementHandler handler;
    DPS_UUID pubId;                 /* Publication identifier */
    DPS_NodeAddress sender;         /* for retained messages - the sender address */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Publication* next;
} DPS_Publication;


#define SEND_SUBSCRIPTIONS_TASK 0x01
#define SEND_PUBLICATIONS_TASK  0x02

typedef struct _DPS_Node {

    uint8_t tasks;                        /* Background tasks that have been scheduled */
    uint16_t port;
    char separators[13];                  /* List of separator characters */

    uv_thread_t thread;                   /* Thread for the event loop */
    uv_loop_t* loop;                      /* uv lib event loop */
    uv_async_t asyncHandler;
    uv_mutex_t nodeLock;                  /* Mutex to protect this node */

    uint64_t ttlBasis;                    /* basis time for expiring retained messages */

    RemoteNode* remoteNodes;              /* Linked list of remote nodes */

    struct {
        DPS_BitVector* needs;             /* Preallocated needs bit vector */
        DPS_BitVector* interests;         /* Preallocated interests bit vector */
    } scratch;

    DPS_CountVector* interests;           /* Tracks all interests for this node */
    DPS_CountVector* needs;               /* Tracks all needs for this node */

    DPS_History history;                  /* History of recently sent publications */

    DPS_Publication* publications;        /* Linked list of local and retained publications */
    DPS_Subscription* subscriptions;      /* Linked list of local subscriptions */

    DPS_MulticastReceiver* mcastReceiver;
    DPS_MulticastSender* mcastSender;

    DPS_NetListener* netListener;         /* TCP listener */

} DPS_Node;

/*
 * Forward declaration
 */
static void RunAsync(uv_async_t* handle);

static void ScheduleTask(DPS_Node* node, uint8_t task)
{
    DPS_DBGTRACE();
    node->tasks |= task;
    uv_async_send(&node->asyncHandler);
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
        DPS_PRINT("Node %d:\n", DPS_GetPortNumber(node));
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            DPS_PRINT("  %s(%d) %s ttl=%d\n", DPS_UUIDToString(&pub->pubId), pub->serialNumber, pub->flags & PUB_FLAG_RETAINED ? "RETAINED" : "", pub->ttl);
        }
    }
}
#endif

#define SameUUID(u1, u2)  (memcmp((u1), (u2), sizeof(DPS_UUID)) == 0)

#define NodeAddressText(a)        DPS_NetAddrText((struct sockaddr*)(&(a)->inaddr))
#define RemoteNodeAddressText(n)  NodeAddressText(&(n)->addr)


static int IsValidSub(DPS_Node* node, const DPS_Subscription* subscription)
{
    DPS_Subscription* sub;
    uv_mutex_lock(&node->nodeLock);
    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        if (sub == subscription) {
            break;
        }
    }
    uv_mutex_unlock(&node->nodeLock);
    return sub != NULL;
}

static int IsValidPub(DPS_Node* node, const DPS_Publication* publication)
{
    DPS_Publication* pub;
    uv_mutex_lock(&node->nodeLock);
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub == publication) {
            break;
        }
    }
    uv_mutex_unlock(&node->nodeLock);
    return pub != NULL;
}

size_t DPS_SubscriptionGetNumTopics(DPS_Node* node, const DPS_Subscription* sub)
{
    return IsValidSub(node, sub) ? sub->numTopics : 0;
}

const char* DPS_SubscriptionGetTopic(DPS_Node* node, const DPS_Subscription* sub, size_t index)
{
    if (IsValidSub(node, sub) && (sub->numTopics > index)) {
        return sub->topics[index];
    } else {
        return NULL;
    }
}

const DPS_UUID* DPS_PublicationGetUUID(DPS_Node* node, const DPS_Publication* pub)
{
    return IsValidPub(node, pub) ? &pub->pubId : NULL;
}

uint32_t DPS_PublicationGetSerialNumber(DPS_Node* node, const DPS_Publication* pub)
{
    return IsValidPub(node, pub) ? pub->serialNumber : 0;
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

static int SameAddr(DPS_NodeAddress* addr, const struct sockaddr* b)
{
    struct sockaddr* a = (struct sockaddr*)&addr->inaddr;

    if (a->sa_family != b->sa_family) {
        return 0;
    }
    if (a->sa_family == AF_INET6) {
        struct sockaddr_in6* ip6a = (struct sockaddr_in6*)a;
        struct sockaddr_in6* ip6b = (struct sockaddr_in6*)b;
        return (ip6a->sin6_port == ip6b->sin6_port) && (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
    } else {
        struct sockaddr_in* ipa = (struct sockaddr_in*)a;
        struct sockaddr_in* ipb= (struct sockaddr_in*)b;
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

static RemoteNode* DeleteRemoteNode(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    RemoteNode* next;

    DPS_DBGTRACE();

    assert(node->remoteNodes);
    assert(remote);

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
        ret = DPS_CountVectorDel(node->interests, remote->inbound.interests);
        assert(ret == DPS_OK);
        DPS_BitVectorFree(remote->inbound.interests);
    }
    if (remote->inbound.needs) {
        ret = DPS_CountVectorDel(node->needs, remote->inbound.needs);
        assert(ret == DPS_OK);
        DPS_BitVectorFree(remote->inbound.needs);
    }
    DPS_BitVectorFree(remote->outbound.interests);
    DPS_BitVectorFree(remote->outbound.needs);
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
    free(pub);
    return next;
}

static DPS_Status UpdateOutboundInterests(DPS_Node* node, RemoteNode* destNode, DPS_BitVector** outInterests)
{
    DPS_Status ret;
    DPS_BitVector* newInterests = NULL;
    DPS_BitVector* newNeeds = NULL;

    DPS_DBGTRACE();

    /*
     * Inbound interests from the node we are updating are excluded from the outbound interests
     */
    if (destNode->inbound.interests) {
        /*
         * TODO- check if this could be optimized to avoid the Del/Add
         */
        ret = DPS_CountVectorDel(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        newInterests = DPS_CountVectorToUnion(node->interests);
        ret = DPS_CountVectorAdd(node->interests, destNode->inbound.interests);
        if (ret != DPS_OK) {
            goto ErrExit;
        }
        /*
         * TODO- check if this could be optimized to avoid the Del/Add
         */
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
     * Don't compute the delta if baseline interests are being sent
     */
    if (destNode->flags & SENDING_BASELINE_INTERESTS) {
        DPS_BitVectorFree(destNode->outbound.interests);
        destNode->outbound.interests = NULL;
    }
    if (destNode->outbound.interests) {
        int same;
        DPS_BitVectorXor(node->scratch.interests, destNode->outbound.interests, newInterests, &same);
        if (same && DPS_BitVectorEquals(destNode->outbound.needs, newNeeds)) {
            *outInterests = NULL;
        } else {
            *outInterests = node->scratch.interests;
        }
        DPS_BitVectorFree(destNode->outbound.interests);
        DPS_BitVectorFree(destNode->outbound.needs);
    } else {
        /*
         * This will ensure the receiver knows this is not a delta
         */
        destNode->flags |= SENDING_BASELINE_INTERESTS;
        *outInterests = newInterests;
    }
    destNode->outbound.interests = newInterests;
    destNode->outbound.needs = newNeeds;

    DPS_DBGPRINT("UpdateOutboundInterests: %s %s\n", RemoteNodeAddressText(destNode), *outInterests ? "Changes" : "No Change");
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

/*
 * Add a remote node or return an existing one
 */
static DPS_Status AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, RemoteNode** remoteOut)
{
    RemoteNode* remote = LookupRemoteNode(node, (struct sockaddr*)&addr->inaddr);
    if (remote) {
        *remoteOut = remote;
        return DPS_ERR_EXISTS;
    }
    remote = calloc(1, sizeof(RemoteNode));
    if (!remote) {
        *remoteOut = NULL;
        return DPS_ERR_RESOURCES;
    }
    DPS_DBGPRINT("Adding new remote node %s\n", NodeAddressText(addr));
    remote->addr.inaddr = addr->inaddr;
    remote->next = node->remoteNodes;
    node->remoteNodes = remote;
    *remoteOut = remote;
    return DPS_OK;
}

static uint32_t UpdateTTLBasis(DPS_Node* node)
{
    uint64_t now = uv_hrtime();
    uint32_t elapsedSeconds = (now - node->ttlBasis) / 1000000000ull;
    node->ttlBasis = now;
    return elapsedSeconds;
}

static void LazyCheckTTLs(DPS_Node* node)
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
        if (pub->ttl > elapsed) {
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
        } else {
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

static void OnSendToComplete(DPS_Node* node, struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        RemoteNode* remote = LookupRemoteNode(node, addr);
        DPS_ERRPRINT("OnSendToComplete %s\n", DPS_ErrTxt(status));
        if (remote) {
            DeleteRemoteNode(node, remote);
            DPS_ERRPRINT("Removed node %s\n", DPS_NetAddrText(addr));
        }
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
        ret = DPS_AppendPubHistory(&node->history, &pub->pubId, pub->serialNumber, pub->ackRequested ? &pub->sender : NULL);
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
        protocol = COAP_OVER_TCP;
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
    CBOR_EncodeUint16(&payload, DPS_GetPortNumber(node));
    CBOR_EncodeInt16(&payload, pub->ttl);
    CBOR_EncodeBytes(&payload, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    CBOR_EncodeUint(&payload, pub->serialNumber);
    CBOR_EncodeBoolean(&payload, pub->ackRequested);

    ret = DPS_BitVectorSerialize(bf, &payload);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, pub->payload, pub->len);
        ret = CoAP_Compose(protocol, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
    }
    if (ret == DPS_OK) {
        if (remote) {
            ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr.inaddr, OnSendToComplete);
            if (ret == DPS_OK) {
                UpdatePubHistory(node, pub);
            } else {
                OnSendToComplete(node, (struct sockaddr*)&remote->addr.inaddr, bufs, A_SIZEOF(bufs), ret);
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
            DPS_DBGPRINT("Sending pub %d to %s\n", pub->serialNumber, RemoteNodeAddressText(sub));
            return SendPublication(node, pub, pubBV, sub);
        }
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->serialNumber, RemoteNodeAddressText(sub));
    }
    return DPS_OK;
}

static DPS_Status SendAcknowledgement(DPS_Node* node, const DPS_UUID* pubId, uint32_t serialNumber, uint8_t* data, size_t len, DPS_NodeAddress* destAddr)
{
    uv_buf_t bufs[3];
    DPS_Status ret;
    CoAP_Option opts[1];
    DPS_Buffer payload;
    size_t allocSize = 8 + sizeof(DPS_UUID) + sizeof(uint32_t) + len;

    DPS_DBGTRACE();

    assert(serialNumber != 0);

    if (!node->netListener) {
        return DPS_ERR_NETWORK;
    }

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_AcknowledgmentURI;
    opts[0].len = sizeof(DPS_AcknowledgmentURI);

    ret = DPS_BufferInit(&payload, NULL, allocSize);
    if (ret != DPS_OK) {
        return ret;
    }
    CBOR_EncodeBytes(&payload, (uint8_t*)pubId, sizeof(DPS_UUID));
    CBOR_EncodeUint32(&payload, serialNumber);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, data, len);
        ret = CoAP_Compose(COAP_OVER_TCP, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
    }
    if (ret == DPS_OK) {
        ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&destAddr->inaddr, OnSendToComplete);
        if (ret != DPS_OK) {
            OnSendToComplete(node, (struct sockaddr*)&destAddr->inaddr, bufs, A_SIZEOF(bufs), ret);
        }
    } else {
        free(payload.base);
    }
    return ret;
}

static DPS_Status DecodeAcknowledgment(DPS_Node* node, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_Publication* pub;
    uint32_t serialNumber;
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
    ret = CBOR_DecodeUint32(buffer, &serialNumber);
    if (ret != DPS_OK) {
        return ret;
    }
    if (serialNumber == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &payload, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->handler && (pub->serialNumber == serialNumber) && SameUUID(&pub->pubId, pubId)) {
            break;
        }
    }
    if (pub) {
        if (pub->handler) {
            pub->handler(node, pub, payload, len);
        }
        return DPS_OK;
    }
    /*
     * Look for in the history record for somewhere to forward the ACK
     */
    ret = DPS_LookupPublisher(&node->history, pubId, serialNumber, &addr);
    if ((ret == DPS_OK) && addr) {
        DPS_DBGPRINT("Forwarding acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), serialNumber, NodeAddressText(addr));
        ret = SendAcknowledgement(node, pubId, serialNumber, payload, len, addr);
    }
    return ret;
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
    LazyCheckTTLs(node);
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
        if (node->mcastSender && (pub->flags & (PUB_FLAG_LOCAL | PUB_FLAG_PUBLISH))) {
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
            } else {
                DPS_DBGPRINT("Expiring pub %s\n", DPS_UUIDToString(&pub->pubId));
                FreePublication(node, pub);
            }
        }
    }
    /*
     * If there are no other retained messages the ttlBasis time will not be set
     */
    if (!node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    DumpPubs(node);
}

/*
 * Run checks of one or more publications against the current subscriptions
 */
static void SendPubs(DPS_Node* node, DPS_Publication* pub)
{
    uv_mutex_lock(&node->nodeLock);
    /*
     * Need something to send and somwhere to send it
     */
    if (node->publications && (node->remoteNodes || node->mcastSender)) {
        if (pub) {
            pub->checkToSend = DPS_TRUE;
        } else {
            /*
             * Check all publications
             */
            for (pub = node->publications; pub != NULL; pub = pub->next) {
                pub->checkToSend = DPS_TRUE;
            }
        }
        ScheduleTask(node, SEND_PUBLICATIONS_TASK);
    }
    uv_mutex_unlock(&node->nodeLock);
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

    for (sub = node->subscriptions; sub != NULL; sub = next) {
        /*
         * Ths current subscription might get freed by the handler so need to hold the next pointer here.
         */
        next = sub->next;
        if (DPS_BitVectorIncludes(pub->bf, sub->bf)) {
            DPS_DBGPRINT("Matched subscription\n");
            UpdatePubHistory(node, pub);
            /*
             * TODO - consider making callback from a worker thread so uv_loop isn't blocked
             */
            sub->handler(node, sub, pub, pub->payload, pub->len);
        }
    }
}

static DPS_Status DecodePublication(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr, int multicast)
{
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_Publication* pub;
    DPS_UUID* pubId;
    uint32_t serialNumber;
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
    ret = CBOR_DecodeUint32(buffer, &serialNumber);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = CBOR_DecodeBoolean(buffer, &ackRequested);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (DPS_PublicationIsStale(&node->history, pubId, serialNumber)) {
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
        if (serialNumber < pub->serialNumber) {
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
    }
    pub->ttl = ttl;
    pub->serialNumber = serialNumber;
    pub->ackRequested = ackRequested;
    pub->flags = PUB_FLAG_PUBLISH;
    AddrSetPort(&pub->sender, addr, port);
    /*
     * We have no reason to hold onto a node for multicast publishers
     */
    if (!multicast) {
        ret = AddRemoteNode(node, &pub->sender, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
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
        pub->payload = realloc(pub->payload, len);
        if (!pub->payload) {
            goto Exit;
        }
        memcpy(pub->payload, payload, len);
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
        DeleteRemoteNode(node, pubNode);
    }
    FreePublication(node, pub);
    return ret;
}

/*
 * Send a subscription request:
 *
 * COAP header
 * COAP URI PATH
 * Payload (CBOR encoded):
 *      Port number we are listening on
 *      Our IPv6 address (filled in later)
 *      Serialized bloom filter
 */
static DPS_Status SendSubscription(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests)
{
    uv_buf_t bufs[3];
    DPS_Status ret;
    CoAP_Option opts[1];
    uint16_t port;
    DPS_Buffer payload;
    DPS_BitVector* needs = remote->outbound.needs;

    size_t allocSize = DPS_BitVectorSerializeMaxSize(needs) + DPS_BitVectorSerializeMaxSize(interests) + 40;

    if (!node->netListener) {
        return DPS_ERR_NETWORK;
    }
    port = DPS_GetPortNumber(node);

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
    CBOR_EncodeUint16(&payload, port);
    CBOR_EncodeBoolean(&payload, remote->flags & REQUIRE_BASELINE_INTERESTS);
    CBOR_EncodeBoolean(&payload, remote->flags & SENDING_BASELINE_INTERESTS);
    ret = DPS_BitVectorSerialize(needs, &payload);
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(interests, &payload);
    }
    if (ret == DPS_OK) {
        ret = CoAP_Compose(COAP_OVER_TCP, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), &payload);
    }
    if (ret != DPS_OK) {
        free(payload.base);
        return ret;
    }
    ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr.inaddr, OnSendToComplete);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
        OnSendToComplete(node, (struct sockaddr*)&remote->addr, bufs, A_SIZEOF(bufs), ret);
    }
    /*
     * Done with these flags
     */
    remote->flags &= ~(REQUIRE_BASELINE_INTERESTS | SENDING_BASELINE_INTERESTS);
    return ret;
}

static void SendSubsTask(DPS_Node* node)
{
    DPS_Status ret;
    RemoteNode* remote;
    RemoteNode* remoteNext;

    DPS_DBGTRACE();

    /*
     * TODO - process one remote at a time to allow for interleaved I/O
     */
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

        ret = UpdateOutboundInterests(node, remote, &newInterests);
        if (ret != DPS_OK) {
            break;
        }
        if (newInterests) {
            ret = SendSubscription(node, remote, newInterests);
            if (ret != DPS_OK) {
                DeleteRemoteNode(node, remote);
                DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(ret));
                continue;
            }
        }
        /*
         * Now that we have updated the remote node if it has no inbound intersts and we didn't
         * explicitly join it there is no reason to keep it around.
         */
        if (!remote->joined && DPS_BitVectorIsClear(remote->inbound.interests)) {
            DPS_DBGPRINT("Remote node has no interests - deleting\n", RemoteNodeAddressText(remote));
            DeleteRemoteNode(node, remote);
        } else {
            /*
             * Clear the directive flags
             */
            remote->flags &= ~(REQUIRE_BASELINE_INTERESTS | SENDING_BASELINE_INTERESTS);
        }
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("SendSubsTask failed %s\n", DPS_ErrTxt(ret));
    }
}

static void SendSubs(DPS_Node* node, RemoteNode* remote)
{
    DPS_DBGTRACE();
    uv_mutex_lock(&node->nodeLock);
    if (node->remoteNodes) {
        if (remote) {
            remote->outbound.checkForUpdates = DPS_TRUE;
        } else {
            /*
             * Check all remotes that have inbound interests
             */
            for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
                remote->outbound.checkForUpdates = remote->inbound.interests != NULL;
            }
        }
        ScheduleTask(node, SEND_SUBSCRIPTIONS_TASK);
    }
    uv_mutex_unlock(&node->nodeLock);
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs)
{
    DPS_DBGTRACE();

    if (remote->inbound.interests) {
        DPS_DBGPRINT("Received interests delta\n");
        DPS_CountVectorDel(node->interests, remote->inbound.interests);
        DPS_BitVectorXor(interests, interests, remote->inbound.interests, NULL);
        DPS_BitVectorFree(remote->inbound.interests);

        DPS_CountVectorDel(node->needs, remote->inbound.needs);
        DPS_BitVectorFree(remote->inbound.needs);
    }
    DPS_CountVectorAdd(node->interests, interests);
    DPS_CountVectorAdd(node->needs, needs);
    remote->inbound.interests = interests;
    remote->inbound.needs = needs;
    remote->inbound.updates = DPS_TRUE;
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
    RemoteNode* remote;
    int reqBaseline;
    int isBaseline;

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
    ret = CBOR_DecodeBoolean(buffer, &reqBaseline);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBoolean(buffer, &isBaseline);
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
    ret = AddRemoteNode(node, &senderAddr, &remote);
    if (ret != DPS_OK) {
        if (ret != DPS_ERR_EXISTS) {
            DPS_BitVectorFree(interests);
            DPS_BitVectorFree(needs);
            return ret;
        }
        if (reqBaseline) {
            remote->flags |= REQUIRE_BASELINE_INTERESTS;
        }
    } else {
        /*
         * Unknown nodes always require baseline interests
         */
        remote->flags |= REQUIRE_BASELINE_INTERESTS;
    }
    /*
     * If the interests are baseline (not deltas) we don't need the old interests
     */
    if (isBaseline) {
        DPS_BitVectorFree(remote->inbound.interests);
        remote->inbound.interests = NULL;
    }
    ret = UpdateInboundInterests(node, remote, interests, needs);
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
        DPS_ERRPRINT("Discarding garbage multicast packet len=%lu\n", len);
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

    ret = CoAP_GetPktLen(COAP_OVER_TCP, data, len, &pktLen);
    if (ret == DPS_OK) {
        if (len < pktLen) {
            /*
             * Need more data
             */
            return pktLen - len;
        }
        ret = CoAP_Parse(COAP_OVER_TCP, data, len, &coap, &payload);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CoAP_Parse failed: ret= %d\n", ret);
            return -len;
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

static void FreeNode(DPS_Node* node)
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
    free(node);
}

static void NodeRun(void* arg)
{
    DPS_Node* node = (DPS_Node*)arg;

    uv_run(node->loop, UV_RUN_DEFAULT);
}


DPS_Status DPS_CreateNode(DPS_Node** nodeOut, int mcast, int tcpPort, const char* separators)
{
    int r;
    DPS_Status ret;
    DPS_Node* node;

    if (!nodeOut || !separators)  {
        return DPS_ERR_NULL;
    }
    node = calloc(1, sizeof(DPS_Node));
    if (!node) {
        return DPS_ERR_RESOURCES;
    }
    node->loop = calloc(1, sizeof(uv_loop_t));
    if (!node->loop) {
        free(node);
        return DPS_ERR_RESOURCES;
    }
    r = uv_loop_init(node->loop);
    if (r) {
        return DPS_ERR_FAILURE;
    }
    strncpy(node->separators, separators, sizeof(node->separators));
    /*
     * For triggering background tasks
     */
    node->asyncHandler.data = node;
    uv_async_init(node->loop, &node->asyncHandler, RunAsync);
    /*
     * Mutex for protecting the public API
     */
    uv_mutex_init(&node->nodeLock);

    node->interests = DPS_CountVectorAlloc();
    node->needs = DPS_CountVectorAllocFH();
    node->scratch.interests = DPS_BitVectorAlloc();
    node->scratch.needs = DPS_BitVectorAllocFH();

    if (!node->interests || !node->needs || !node->scratch.interests || !node->scratch.needs) {
        FreeNode(node);
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_InitUUID();
    if (ret != DPS_OK) {
        FreeNode(node);
        return ret;
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_RECV) {
        node->mcastReceiver = DPS_MulticastStartReceive(node, OnMulticastReceive);
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_SEND) {
        node->mcastSender = DPS_MulticastStartSend(node);
    }
    node->netListener = DPS_NetStartListening(node, tcpPort, OnNetReceive);
    if (!node->netListener) {
        DPS_ERRPRINT("Failed to initialize listener on TCP port %d\n", tcpPort);
        FreeNode(node);
        return DPS_ERR_NETWORK;
    }
    r = uv_thread_create(&node->thread, NodeRun, node);
    if (r) {
        DPS_ERRPRINT("Failed to create node thread\n");
        FreeNode(node);
        return DPS_ERR_FAILURE;
    }
    *nodeOut = node;
    return DPS_OK;
}

uv_loop_t* DPS_GetLoop(DPS_Node* node)
{
    return node->loop;
}

uint16_t DPS_GetPortNumber(DPS_Node* node)
{
    if (node) {
        if (!node->port && node->netListener) {
            node->port = DPS_NetGetListenerPort(node->netListener);
        }
        return node->port;
    } else {
        return 0;
    }

}

void DPS_StopNode(DPS_Node* node)
{
    if (node->mcastReceiver) {
        node->mcastReceiver = NULL;
        DPS_MulticastStopReceive(node->mcastReceiver);
    }
    if (node->mcastSender) {
        DPS_MulticastStopSend(node->mcastSender);
        node->mcastSender = NULL;
    }
    if (node->netListener) {
        DPS_NetStopListening(node->netListener);
        node->netListener = NULL;
    }
}

void DPS_DestroyNode(DPS_Node* node)
{
    if (uv_thread_join(&node->thread) == 0) {
        FreeNode(node);
    }
}

DPS_Status DPS_CreatePublication(DPS_Node* node, char* const* topics, size_t numTopics, DPS_AcknowledgementHandler handler, DPS_Publication** publication)
{
    size_t i;
    DPS_Publication* pub;
    DPS_Status ret = DPS_OK;

    if (!node || !topics || !publication) {
        return DPS_ERR_NULL;
    }
    *publication = NULL;
    /*
     * Must have a topic
     */
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    DPS_DBGPRINT("Creating publication with %lu topics\n", numTopics);
    DumpTopics(topics, numTopics);
    /*
     * Create the publication
     */
    pub = calloc(1, sizeof(DPS_Publication));
    if (!pub) {
        return DPS_ERR_RESOURCES;
    }
    DPS_GenerateUUID(&pub->pubId);
    pub->bf = DPS_BitVectorAlloc();
    if (!pub->bf) {
        free(pub);
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
    uv_mutex_lock(&node->nodeLock);
    pub->next = node->publications;
    node->publications = pub;
    if (ret == DPS_OK) {
        *publication = pub;
    } else {
        FreePublication(node, pub);
    }
    uv_mutex_unlock(&node->nodeLock);
    return ret;
}

DPS_Status DPS_Publish(DPS_Node* node, DPS_Publication* pub, void* payload, size_t len, int16_t ttl, void** oldPayload)
{
    DPS_DBGTRACE();

    if (!node || !pub) {
        return DPS_ERR_NULL;
    }
    /*
     * Check publication is listed and is local
     */
    if (!IsValidPub(node, pub) || !(pub->flags & PUB_FLAG_LOCAL)) {
        return DPS_ERR_MISSING;
    }
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
    ++pub->serialNumber;

    if ((pub->ttl > 0) && !node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    SendPubs(node, pub);
    return DPS_OK;
}

DPS_Status DPS_DestroyPublication(DPS_Node* node, DPS_Publication* pub, void** payload)
{
    DPS_DBGTRACE();
    if (!node || !pub || !payload) {
        return DPS_ERR_NULL;
    }
    *payload = NULL;
    /*
     * Check publication is listed and is local
     */
    if (!IsValidPub(node, pub) || !(pub->flags & PUB_FLAG_LOCAL)) {
        return DPS_ERR_MISSING;
    }
    *payload = pub->payload;
    FreePublication(node, pub);
    return DPS_ERR_OK;
}

DPS_Status DPS_Join(DPS_Node* node, DPS_NodeAddress* addr)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote;

    DPS_DBGTRACE();
    if (!addr || !node) {
        return DPS_ERR_NULL;
    }
    uv_mutex_lock(&node->nodeLock);
    ret = AddRemoteNode(node, addr, &remote);
    if (remote) {
        remote->joined = DPS_TRUE;
    }
    if (ret != DPS_OK) {
        if (ret == DPS_ERR_EXISTS) {
            DPS_ERRPRINT("Node at %s already joined\n", DPS_NodeAddressText(addr));
            ret = DPS_OK;
        }
        uv_mutex_unlock(&node->nodeLock);
    } else {
        remote->flags |= (REQUIRE_BASELINE_INTERESTS | SENDING_BASELINE_INTERESTS);
        uv_mutex_unlock(&node->nodeLock);
        SendSubs(node, remote);
    }
    return ret;
}

DPS_Status DPS_Leave(DPS_Node* node, DPS_NodeAddress* addr)
{
    DPS_Status status;
    RemoteNode* remote;

    uv_mutex_lock(&node->nodeLock);
    remote = LookupRemoteNode(node, (struct sockaddr*)&addr->inaddr);
    if (remote) {
        DeleteRemoteNode(node, remote);
        status = DPS_OK;
    } else {
        status = DPS_ERR_MISSING;
    }
    uv_mutex_unlock(&node->nodeLock);
    return status;
}

DPS_Status DPS_AcknowledgePublication(DPS_Node* node, const DPS_UUID* pubId, uint32_t serialNumber, void* payload, size_t len)
{
    DPS_Status ret = DPS_OK;
    DPS_NodeAddress* addr = NULL;

    if (!node || !pubId) {
        return DPS_ERR_NULL;
    }
    ret = DPS_LookupPublisher(&node->history, pubId, serialNumber, &addr);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!addr) {
        return DPS_ERR_NO_ROUTE;
    }
    DPS_DBGPRINT("Sending acknowledgement for %s/%d to %s\n", DPS_UUIDToString(pubId), serialNumber, NodeAddressText(addr));
    return SendAcknowledgement(node, pubId, serialNumber, payload, len, addr);
}

DPS_Status DPS_Subscribe(DPS_Node* node, char* const* topics, size_t numTopics, DPS_PublicationHandler handler, DPS_Subscription** subscription)
{
    size_t i;
    DPS_Subscription* sub;
    DPS_Status ret = DPS_OK;

    if (!node || !topics || !handler || !subscription) {
        return DPS_ERR_NULL;
    }
    *subscription = NULL;
    /*
     * Must have a topic
     */
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    /*
     * Create the subscription
     */
    sub = malloc(sizeof(DPS_Subscription) + sizeof(char*) * (numTopics - 1));
    if (!sub) {
        return DPS_ERR_RESOURCES;
    }
    sub->numTopics = 0;
    sub->handler = handler;
    sub->bf = DPS_BitVectorAlloc();
    sub->needs = DPS_BitVectorAllocFH();
    if (!sub->bf || !sub->needs) {
        FreeSubscription(sub);
        return DPS_ERR_RESOURCES;
    }
    /*
     * Add the topics to the subscription and the bloom filter
     */
    for (i = 0; i < numTopics; ++i) {
        size_t len = strlen(topics[i]);
        sub->topics[i] = malloc(len + 1);
        if (!sub->topics[i]) {
            ret = DPS_ERR_RESOURCES;
            break;
        }
        ++sub->numTopics;
        memcpy(sub->topics[i], topics[i], len + 1);
        ret = DPS_AddTopic(sub->bf, sub->topics[i], node->separators, DPS_Sub);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        FreeSubscription(sub);
    } else {
        DPS_DBGPRINT("Subscribing to %lu topics\n", numTopics);
        DumpTopics(sub->topics, sub->numTopics);

        DPS_BitVectorFuzzyHash(sub->needs, sub->bf);

        /*
         * Protect the node while we update it
         */
        uv_mutex_lock(&node->nodeLock);
        sub->next = node->subscriptions;
        node->subscriptions = sub;
        *subscription = sub;
        ret = DPS_CountVectorAdd(node->interests, sub->bf);
        if (ret == DPS_OK) {
            ret = DPS_CountVectorAdd(node->needs, sub->needs);
        }
        uv_mutex_unlock(&node->nodeLock);

        if (ret == DPS_OK) {
            SendSubs(node, NULL);
        }
    }
    return ret;
}

DPS_Status DPS_SubscribeCancel(DPS_Node* node, DPS_Subscription* sub)
{
    DPS_Status ret;

    if (!node || !sub) {
        return DPS_ERR_NULL;
    }
    /*
     * Protect the node while we update it
     */
    uv_mutex_lock(&node->nodeLock);
    if (!IsValidSub(node, sub)) {
        uv_mutex_unlock(&node->nodeLock);
        return DPS_ERR_MISSING;
    }
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
    ret = DPS_CountVectorDel(node->interests, sub->bf);
    assert(ret == DPS_OK);
    ret = DPS_CountVectorDel(node->needs, sub->needs);
    assert(ret == DPS_OK);
    uv_mutex_unlock(&node->nodeLock);

    DPS_DBGPRINT("Unsubscribing from %lu topics\n", sub->numTopics);
    DumpTopics(sub->topics, sub->numTopics);
    FreeSubscription(sub);

    SendSubs(node, NULL);

    return DPS_OK;
}

static void RunAsync(uv_async_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    DPS_DBGTRACE();

    uv_mutex_lock(&node->nodeLock);
    while (node->tasks) {
        if (node->tasks & SEND_SUBSCRIPTIONS_TASK) {
            node->tasks &= ~SEND_SUBSCRIPTIONS_TASK;
            SendSubsTask(node);
            continue;
        }
        if (node->tasks & SEND_PUBLICATIONS_TASK) {
            node->tasks &= ~SEND_PUBLICATIONS_TASK;
            SendPubsTask(node);
            continue;
        }
    }
    uv_mutex_unlock(&node->nodeLock);
}

DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service, DPS_NodeAddress* addr)
{
    DPS_Status dpsRet = DPS_OK;
    int ret;
    uv_getaddrinfo_t info;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    if (!host) {
        host = "localhost";
    }
    ret = uv_getaddrinfo(node->loop, &info, NULL, host, service, &hints);
    if (ret) {
        DPS_ERRPRINT("uv_getaddrinfo call error %s\n", uv_err_name(ret));
        dpsRet = DPS_ERR_NETWORK;
    } else {
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)info.addrinfo->ai_addr;
        if (ip6->sin6_family == AF_INET6) {
            memcpy(&addr->inaddr, ip6, sizeof(*ip6));
            freeaddrinfo(info.addrinfo);
        } else {
            dpsRet = DPS_ERR_NETWORK;
        }
    }
    return dpsRet;
}

void DPS_DumpSubscriptions(DPS_Node* node)
{
    DPS_Subscription* sub;

    DPS_DBGPRINT("Current subscriptions:\n");
    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        DumpTopics(sub->topics, sub->numTopics);
    }
}
