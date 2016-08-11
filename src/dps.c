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

typedef struct _RemoteNode {
    uint8_t joined;                    /* True if this is a node that was explicitly joined */
    DPS_NodeAddress addr;
    struct {
        DPS_BitVector* needs;          /* Bit vector of needs received from  this remote node */
        DPS_BitVector* interests;      /* Bit vector of interests received from  this remote node */
    } inbound;
    struct {
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


#define PUB_FLAG_PUBLISH  (0x01) /* Set if publication has not not yet been published */
#define PUB_FLAG_RETAINED (0x02) /* Set if the publication is a retained publication */

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
    uint8_t ackRequested;           /* TRUE if an ack was requested by the publisher */
    int16_t ttl;                    /* Remaining time-to-live in seconds */
    uint32_t serialNumber;          /* Serial number for this publication */
    uint8_t* payload;
    size_t len;
    DPS_AcknowledgementHandler handler;
    DPS_UUID pubId;                 /* Publication identifier */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Publication* next;
} DPS_Publication;

typedef struct _DPS_Node {

    uint16_t port;
    char separators[13];                  /* List of separator characters */

    uv_loop_t* loop;                      /* uv lib event loop */
    uv_timer_t shutdownTimer;             /* for graceful shut down */

    uint64_t ttlBasis;                    /* basis time for expiring retained messages */

    RemoteNode* remoteNodes;              /* Linked list of remote nodes */

    struct {
        DPS_BitVector* fh;                /* Preallocated bit vector */
        DPS_BitVector* bf;                /* Preallocated bit vector */
    } scratch;

    DPS_CountVector* interests;           /* Tracks all interests for this node */
    DPS_CountVector* needs;               /* Tracks all needs for this node */

    DPS_History history;                  /* History of recently sent publications */

    DPS_Publication* publications;        /* Linked list of local and retained publications */
    DPS_Subscription* subscriptions;      /* Linked list of local subscriptions */

    DPS_MulticastReceiver* mcastReceiver;
    DPS_MulticastSender* mcastSender;

    DPS_NetListener* netListener;         /* TCP listener */

    DPS_Publication* currentPub;          /* Publication currently be passed to callback handler */

} DPS_Node;

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

#define NodeAddressText(a)        DPS_NetAddrText((struct sockaddr*)(&(a)->inaddr))
#define RemoteNodeAddressText(n)  NodeAddressText(&(n)->addr)

size_t DPS_SubscriptionGetNumTopics(DPS_Node* node, DPS_Subscription* subscription)
{
    DPS_Subscription* sub;

    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        if (sub == subscription) {
            return sub->numTopics;
        }
    }
    return 0;
}

const char* DPS_SubscriptionGetTopic(DPS_Node* node, DPS_Subscription* subscription, size_t index)
{
    DPS_Subscription* sub;

    for (sub = node->subscriptions; sub != NULL; sub = sub->next) {
        if (sub == subscription) {
            if (sub->numTopics > index) {
                return sub->topics[index];
            } else {
                return NULL;
            }
        }
    }
    return NULL;
}

const DPS_UUID* DPS_PublicationGetUUID(DPS_Node* node, DPS_Publication* publication)
{
    DPS_Publication* pub = publication;
    if (pub != node->currentPub) {
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            if (pub == publication) {
                break;
            }
        }
    }
    return pub ? &pub->pubId : NULL;
}

uint32_t DPS_PublicationGetSerialNumber(DPS_Node* node, DPS_Publication* publication)
{
    DPS_Publication* pub = publication;
    if (pub != node->currentPub) {
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            if (pub == publication) {
                break;
            }
        }
    }
    return pub ? pub->serialNumber : 0;
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

static DPS_Status UpdateOutboundInterests(DPS_Node* node, RemoteNode* destNode, int* updates)
{
    DPS_Status ret;
    DPS_BitVector* newInterests = NULL;
    DPS_BitVector* newNeeds = NULL;

    DPS_DBGTRACE();

    *updates = DPS_TRUE;
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
    if (destNode->outbound.interests) {
        assert(destNode->outbound.needs);
        if (DPS_BitVectorEquals(destNode->outbound.interests, newInterests) && DPS_BitVectorEquals(destNode->outbound.needs, newNeeds)) {
            *updates = DPS_FALSE;
        }
        DPS_BitVectorFree(destNode->outbound.interests);
        DPS_BitVectorFree(destNode->outbound.needs);
    }
    destNode->outbound.interests = newInterests;
    destNode->outbound.needs = newNeeds;

    DPS_DBGPRINT("UpdateOutboundInterests: %s %s\n", RemoteNodeAddressText(destNode), *updates ? "Updates" : "No Change");
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
        next = pub->next;
        if (pub->ttl <= 0) {
            continue;
        }
        if (pub->ttl > elapsed) {
            pub->ttl -= elapsed;
            ++numTTLs;
            continue;
        }
        /*
         * When a ttl expires retained publications are freed, local (not retained)
         * publications are disabled by clearing the PUBLISH flag.
         */
        if (pub->flags & PUB_FLAG_RETAINED) {
            DPS_DBGPRINT("Expiring pub %s\n", DPS_UUIDToString(&pub->pubId));
            FreePublication(node, pub);
        } else {
            pub->flags &= ~PUB_FLAG_PUBLISH;
        }
    }
    /*
     * If there are no TTLs to check clear the ttlBasis
     */
    if (numTTLs == 0) {
        node->ttlBasis = 0;
    }
}

static DPS_Status LookupRetainedPub(DPS_Node* node, DPS_Publication* tmpPub, DPS_Publication** retained)
{
    DPS_Publication* pub;

    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && (memcmp(&pub->pubId, &tmpPub->pubId, sizeof(DPS_UUID)) == 0)) {
            break;
        }
    }
    *retained = pub;
    if (!pub) {
        return DPS_OK;
    }
    /*
     * The bit vector of a retained publication cannot change
     */
    if (!DPS_BitVectorEquals(tmpPub->bf, pub->bf)) {
        DPS_ERRPRINT("Inconsistent bit vector in retained pub");
        return DPS_ERR_INVALID;
    }
    if (tmpPub->serialNumber <= pub->serialNumber) {
        DPS_ERRPRINT("Publication is stale");
        return DPS_ERR_STALE;
    }
    return DPS_ERR_OK;
}


static DPS_Status ExpirePublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Publication* retained;
    DPS_Status ret = LookupRetainedPub(node, pub, &retained);
    if ((ret == DPS_OK) && retained) {
        DPS_DBGPRINT("Expiring pub %s\n", DPS_UUIDToString(&pub->pubId));
        FreePublication(node, retained);
    }
    return ret;
}

static DPS_Status RetainPublication(DPS_Node* node, DPS_Publication* pub)
{
    DPS_Status ret = DPS_OK;
    DPS_Publication* retained;

    DPS_DBGTRACE();

    /*
     * Removed any stale retained pubs
     */
    LazyCheckTTLs(node);

    ret = LookupRetainedPub(node, pub, &retained);
    if (ret != DPS_OK) {
        return ret;
    }
    if (retained) {
        /*
         * The bit vector will be replace below
         */
        DPS_BitVectorFree(retained->bf);
        retained->bf = NULL;
        if (retained->payload) {
            free(retained->payload);
            retained->payload = NULL;
            retained->len = 0;
        }
        DPS_DBGPRINT("Updating retained pub %s\n", DPS_UUIDToString(&pub->pubId));
    } else {
        retained = calloc(1, sizeof(DPS_Publication));
        if (!retained) {
            return DPS_ERR_RESOURCES;
        }
        retained->next = node->publications;
        node->publications = retained;
        DPS_DBGPRINT("Retaining pub %s\n", DPS_UUIDToString(&pub->pubId));
    }
    *retained = *pub;
    if (pub->len) {
        retained->payload = malloc(pub->len);
        if (!retained->payload) {
            FreePublication(node, retained);
            return DPS_ERR_RESOURCES;
        }
        memcpy(retained->payload, pub->payload, pub->len);
    }
    retained->flags = (PUB_FLAG_RETAINED | PUB_FLAG_PUBLISH);
    /*
     * We have taken ownership of the Bloom filter
     */
    pub->bf = NULL;
    /*
     * If there are no other retained messages the checkTTL flag will not be set
     */
    if (!node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    return DPS_OK;
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
            if (ret != DPS_OK) {
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
    DPS_BitVectorIntersection(node->scratch.bf, pub->bf, sub->inbound.interests);
    DPS_BitVectorFuzzyHash(node->scratch.fh, node->scratch.bf);
    if (DPS_BitVectorIncludes(node->scratch.fh, sub->inbound.needs)) {
        /*
         * If the publication will be retained we send the full publication Bloom
         * filter otherwise we only send the intersection with the subscription interests.
         * The reason for sending the full publication is that we don't know what the
         * interests will be over the lifetime of the publication.
         */
        return (pub->flags & PUB_FLAG_RETAINED) ? pub->bf : node->scratch.bf;
    } else {
        return NULL;
    }
}

static DPS_Status ForwardPubToOneSub(DPS_Node* node, DPS_Publication* pub, RemoteNode* sub)
{
    DPS_BitVector* pubBV = PubSubMatch(node, pub, sub);
    if (pubBV) {
        DPS_DBGPRINT("Forwarded pub %d to %s\n", pub->serialNumber, RemoteNodeAddressText(sub));
        return SendPublication(node, pub, pubBV, sub);
    } else {
        DPS_DBGPRINT("Rejected pub %d for %s\n", pub->serialNumber, RemoteNodeAddressText(sub));
        return DPS_OK;
    }
}

/*
 * Forward a publication to a specific subscriber or all matching subscribers
 */
static DPS_Status ForwardPubToSubs(DPS_Node* node, DPS_Publication* pub, RemoteNode* pubNode, int* sendCount)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = node->remoteNodes;

    DPS_DBGTRACE();

    *sendCount = 0;

    if (!pub->flags & PUB_FLAG_PUBLISH) {
        return DPS_OK;
    }
    while (remote) {
        /*
         * Ignore nodes that are not currently subscribers
         */
        if (!remote->inbound.interests) {
            remote = remote->next;
            continue;
        }
        /*
         * Don't send a publication back to its publisher
         */
        if (pubNode && SameAddr(&pubNode->addr, (struct sockaddr*)&remote->addr)) {
            DPS_DBGPRINT("ForwardPubToSubs don't send pub back to publisher\n");
            remote = remote->next;
            continue;
        }
        ret = ForwardPubToOneSub(node, pub, remote);
        if (ret != DPS_OK) {
            remote = DeleteRemoteNode(node, remote);
        } else {
            (*sendCount)++;
            remote = remote->next;
        }
    }
    return ret;
}

static DPS_Status SendAcknowledgement(DPS_Node* node, DPS_UUID* pubId, uint32_t serialNumber, uint8_t* data, size_t len, DPS_NodeAddress* destAddr)
{
    uv_buf_t bufs[3];
    DPS_Status ret;
    CoAP_Option opts[1];
    DPS_Buffer payload;
    size_t allocSize = 8 + sizeof(DPS_UUID) + sizeof(uint32_t) + len;

    DPS_DBGTRACE();

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
    CBOR_EncodeUint32(&payload, serialNumber);
    CBOR_EncodeBytes(&payload, (uint8_t*)pubId, sizeof(DPS_UUID));
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, data, len);
        ret = CoAP_Compose(COAP_OVER_TCP, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), &payload);
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
    ret = CBOR_DecodeBytes(buffer, &payload, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * See if this is an ACK for a local publication
     */
    for (pub = node->publications; pub != NULL; pub = pub->next) {
        if (pub->handler && (pub->serialNumber == serialNumber) && (memcmp(&pub->pubId, pubId, sizeof(DPS_UUID)) == 0)) {
            break;
        }
    }
    /*
     * If there is a local handler call it and we are done
     */
    if (pub->handler) {
        pub->handler(node, pub, payload, len);
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

static DPS_Status DecodePublication(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr, int multicast)
{
    DPS_Status ret;
    RemoteNode* pubNode = NULL;
    uint16_t port;
    DPS_NodeAddress senderAddr;
    DPS_Publication pub;
    DPS_UUID* pubId;
    int ackRequested;
    size_t len;

    DPS_DBGTRACE();

    memset(&pub, 0, sizeof(pub));

    ret = CBOR_DecodeUint16(buffer, &port);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeInt16(buffer, &pub.ttl);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBytes(buffer, (uint8_t**)&pubId, &len);
    if (ret != DPS_OK) {
        return ret;
    }
    if (len != sizeof(DPS_UUID)) {
        return DPS_ERR_INVALID;
    }
    pub.pubId = *pubId;
    ret = CBOR_DecodeUint32(buffer, &pub.serialNumber);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBoolean(buffer, &ackRequested);
    if (ret != DPS_OK) {
        return ret;
    }
    pub.ackRequested = ackRequested;
    if (DPS_PublicationIsStale(&node->history, &pub.pubId, pub.serialNumber)) {
        DPS_DBGPRINT("Publication is stale\n");
        return DPS_OK;
    }
    AddrSetPort(&senderAddr, addr, port);
    /*
     * We have no reason to hold onto a node for multicast publishers
     */
    if (!multicast) {
        ret = AddRemoteNode(node, &senderAddr, &pubNode);
        if (ret == DPS_ERR_EXISTS) {
            DPS_DBGPRINT("Updating existing node\n");
            ret = DPS_OK;
        }
        if (ret != DPS_OK) {
            return ret;
        }
    }
    pub.bf = DPS_BitVectorAlloc();
    if (!pub.bf) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_BitVectorDeserialize(pub.bf, buffer);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * Note: pub.payload is a pointer into the buffer so must be copied
     */
    ret = CBOR_DecodeBytes(buffer, &pub.payload, &pub.len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (ret == DPS_OK) {
        int sendCount;
        DPS_Subscription* sub;
        DPS_Subscription* next;
        /*
         * Check if there is a local subscription for this publication
         * Note that we don't deliver expired publications.
         */
        if (pub.ttl >= 0) {
            for (sub = node->subscriptions; sub != NULL; sub = next) {
                /*
                 * Ths current subscription might get freed by the handler so need to hold the next pointer here.
                 */
                next = sub->next;
                if (DPS_BitVectorIncludes(pub.bf, sub->bf)) {
                    DPS_DBGPRINT("Matched subscription\n");
                    node->currentPub = &pub;
                    sub->handler(node, sub, &pub, pub.payload, pub.len);
                    node->currentPub = NULL;
                }
            }
        }
        pub.flags = PUB_FLAG_PUBLISH;
        /*
         * Forward the publication to matching remote subscribers
         */
        ret = ForwardPubToSubs(node, &pub, pubNode, &sendCount);
        /*
         * Record history for this publication if it was forwarded to at least one subscriber
         */
        if (sendCount > 0) {
            DPS_AppendPubHistory(&node->history, &pub.pubId, pub.serialNumber, ackRequested ? &senderAddr : NULL);
        }
        /*
         * Check if the publication should be retained or expired
         */
        if (pub.ttl <= 0) {
            ret = ExpirePublication(node, &pub);
        } else {
            ret = RetainPublication(node, &pub);
        }

    }

Exit:
    /*
     * Delete the publisher node if it is sending bad data
     */
    if (ret == DPS_ERR_INVALID) {
        DeleteRemoteNode(node, pubNode);
    }
    DPS_BitVectorFree(pub.bf);
    DPS_FreshenHistory(&node->history);
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
static DPS_Status SendSubscription(DPS_Node* node, RemoteNode* remote)
{
    uv_buf_t bufs[3];
    DPS_Status ret;
    CoAP_Option opts[1];
    uint16_t port;
    DPS_Buffer payload;
    size_t allocSize = DPS_BitVectorSerializeMaxSize(remote->outbound.needs) + DPS_BitVectorSerializeMaxSize(remote->outbound.interests) + 32;

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
    ret = DPS_BitVectorSerialize(remote->outbound.needs, &payload);
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(remote->outbound.interests, &payload);
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
    return ret;
}


static DPS_Status FloodSubscriptions(DPS_Node* node, RemoteNode* newNode)
{
    RemoteNode* remote;
    DPS_Status ret;

    DPS_DBGTRACE();

    /*
     * Forward subscription to all remote nodes with interestss
     */
    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        DPS_Status sendRet;
        int updates;

        if (!remote->inbound.interests) {
            continue;
        }
        ret = UpdateOutboundInterests(node, remote, &updates);
        if (ret != DPS_OK) {
            break;
        }
        /*
         * New nodes always receive current interests, existing nodes only get updates
         */
        if ((remote != newNode) && !updates) {
            continue;
        }
        sendRet = SendSubscription(node, remote);
        if (sendRet != DPS_OK) {
            DPS_ERRPRINT("Failed to send subscription request %s\n", DPS_ErrTxt(sendRet));
        }
    }
    return ret;
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs)
{
    DPS_DBGTRACE();
    if (remote->inbound.interests) {
        DPS_CountVectorDel(node->interests, remote->inbound.interests);
        DPS_CountVectorDel(node->needs, remote->inbound.needs);
        DPS_BitVectorFree(remote->inbound.interests);
        DPS_BitVectorFree(remote->inbound.needs);
    }
    DPS_CountVectorAdd(node->interests, interests);
    DPS_CountVectorAdd(node->needs, needs);
    remote->inbound.interests = interests;
    remote->inbound.needs = needs;
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
    int isNew;

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
        isNew = DPS_FALSE;
    } else {
        isNew = DPS_TRUE;
    }
    ret = UpdateInboundInterests(node, remote, interests, needs);
    if (ret == DPS_OK) {
        ret = FloodSubscriptions(node, isNew ? remote : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("FloodSubscriptions failed %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }
    /*
     * Expire any stale retained publications
     */
    LazyCheckTTLs(node);
    /*
     * If this is not a remote node we explicitly joined and it has no inbound
     * interests there is no reason to keep this remote node.
     */
    if (!remote->joined && DPS_BitVectorIsClear(remote->inbound.interests)) {
        DPS_DBGPRINT("Remote node has no interests - deleting\n", RemoteNodeAddressText(remote));
        DeleteRemoteNode(node, remote);
        return DPS_OK;
    }
    /*
     * TODO - avoid sending duplicate publications
     *
     * If the remote already exists and the new interests are
     * not a subset of the existing interests:
     *
     * 1) Determine which publications matched the old interests.
     *
     * 2) For each publication that did not match the old interests
     *    check if the publication matches the new interests
     */
    if (ret == DPS_OK) {
        DPS_Publication* pub;
        /*
         * Check if any local or retained publications need to be forwarded to this subscriber
         */
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            DPS_Status pubRet = ForwardPubToOneSub(node, pub, remote);
            if (pubRet != DPS_OK) {
                DPS_ERRPRINT("ForwardPubToOneSub failed %s\n", DPS_ErrTxt(pubRet));
            }
        }
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
    DPS_BitVectorFree(node->scratch.bf);
    DPS_BitVectorFree(node->scratch.fh);
    DPS_HistoryFree(&node->history);
    free(node);
}

DPS_Node* DPS_InitNode(int mcast, int tcpPort, const char* separators)
{
    DPS_Status ret;
    DPS_Node* node = calloc(1, sizeof(DPS_Node));

    if (!node) {
        return NULL;
    }
    strncpy(node->separators, separators, sizeof(node->separators));
    node->loop = uv_default_loop();
    /*
     * Initialize the shutdown timer
     */
    node->shutdownTimer.data = node;
    uv_timer_init(node->loop, &node->shutdownTimer);

    node->interests = DPS_CountVectorAlloc();
    node->needs = DPS_CountVectorAllocFH();
    node->scratch.bf = DPS_BitVectorAlloc();
    node->scratch.fh = DPS_BitVectorAllocFH();

    if (!node->interests || !node->needs || !node->scratch.bf || !node->scratch.fh) {
        FreeNode(node);
        return NULL;
    }
    ret = DPS_InitUUID();
    if (ret != DPS_OK) {
        FreeNode(node);
        return NULL;
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_RECV) {
        node->mcastReceiver = DPS_MulticastStartReceive(node, OnMulticastReceive);
    }
    if (mcast & DPS_MCAST_PUB_ENABLE_SEND) {
        node->mcastSender = DPS_MulticastStartSend(node);
    }
    node->netListener = DPS_NetStartListening(node, tcpPort, OnNetReceive);
    return node;
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

#define SHUTDOWN_TIMEOUT1  500
#define SHUTDOWN_TIMEOUT2   50

static void TerminateOnTimeout(uv_timer_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    assert(&node->shutdownTimer == handle);

    if (node->netListener) {
        DPS_NetStopListening(node->netListener);
        node->netListener = NULL;
    }
    uv_timer_stop(handle);

    if (uv_loop_alive(handle->loop)) {
        uv_timer_start(&node->shutdownTimer, TerminateOnTimeout, SHUTDOWN_TIMEOUT2, 0);
    } else {
        FreeNode(node);
    }
}

void DPS_TerminateNode(DPS_Node* node)
{
    if (node->mcastReceiver) {
        DPS_MulticastStopReceive(node->mcastReceiver);
    }
    if (node->mcastSender) {
        DPS_MulticastStopSend(node->mcastSender);
    }
    uv_timer_start(&node->shutdownTimer, TerminateOnTimeout, SHUTDOWN_TIMEOUT1, 0);
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
    pub->next = node->publications;
    node->publications = pub;

    for (i = 0; i < numTopics; ++i) {
        ret = DPS_AddTopic(pub->bf, topics[i], node->separators, DPS_Pub);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret == DPS_OK) {
        *publication = pub;
    } else {
        FreePublication(node, pub);
    }
    return ret;
}

DPS_Status DPS_Publish(DPS_Node* node, DPS_Publication* pub, void* payload, size_t len, int16_t ttl, void** oldPayload)
{
    int sendCount = 0;
    DPS_Status ret = DPS_OK;

    DPS_DBGTRACE();

    if (!node || !pub) {
        return DPS_ERR_NULL;
    }
    /*
     * Return the existing payload pointer if requested
     */
    if (oldPayload) {
        *oldPayload = payload;
    }
    pub->payload = payload;
    pub->len = len;
    pub->flags = PUB_FLAG_PUBLISH;
    pub->ttl = ttl >= 0 ? ttl : -1;
    ++pub->serialNumber;

    if ((pub->ttl > 0) && !node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    if (node->mcastSender) {
        ret = SendPublication(node, pub, pub->bf, NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("SendPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
        }
    }
    ret = ForwardPubToSubs(node, pub, NULL, &sendCount);

    if (ret != DPS_OK) {
        DPS_ERRPRINT("ForwardPubToSubs returned %s\n", DPS_ErrTxt(ret));
    }
    return ret;
}

DPS_Status DPS_DestroyPublication(DPS_Node* node, DPS_Publication* pub, void** payload)
{
    DPS_Publication* list;

    DPS_DBGTRACE();
    if (!node || !pub || !payload) {
        return DPS_ERR_NULL;
    }
    *payload = NULL;
    /*
     * Check publication is listed
     */
    for (list = node->publications; list != pub; list = list->next) { }
    if (!list) {
        return DPS_ERR_MISSING;
    }
    *payload = pub->payload;
    FreePublication(node, pub);
    return DPS_ERR_OK;
}

static DPS_Status SendInitialSubscription(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    int updates;

    DPS_DBGTRACE();

    assert(!remote->outbound.interests);
    assert(!remote->outbound.needs);

    ret = UpdateOutboundInterests(node, remote, &updates);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Send subscriptions to a specific remote node
     */
    ret = SendSubscription(node, remote);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
    }
    return ret;
}

DPS_Status DPS_Join(DPS_Node* node, DPS_NodeAddress* addr)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote;

    if (!addr || !node) {
        return DPS_ERR_NULL;
    }
    ret = AddRemoteNode(node, addr, &remote);
    if (remote) {
        remote->joined = DPS_TRUE;
    }
    if (ret != DPS_OK) {
        if (ret == DPS_ERR_EXISTS) {
            DPS_ERRPRINT("Node at %s already joined\n", DPS_NodeAddressText(addr));
            ret = DPS_OK;
        }
    } else {
        if (ret == DPS_OK) {
            ret = SendInitialSubscription(node, remote);
        }
        if (ret != DPS_OK) {
            DeleteRemoteNode(node, remote);
        }
    }
    return ret;
}

DPS_Status DPS_Leave(DPS_Node* node, DPS_NodeAddress* addr)
{
    RemoteNode* remote = LookupRemoteNode(node, (struct sockaddr*)&addr->inaddr);
    if (remote) {
        DeleteRemoteNode(node, remote);
        return DPS_OK;
    } else {
        return DPS_ERR_MISSING;
    }
}

DPS_Status DPS_AcknowledgePublication(DPS_Node* node, DPS_UUID* pubId, uint32_t serialNumber, uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_OK;
    DPS_NodeAddress* addr;

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
    return SendAcknowledgement(node, pubId, serialNumber, data, len, addr);
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
        sub->next = node->subscriptions;
        node->subscriptions = sub;
        *subscription = sub;
        /*
         * TODO - optimization - check for no changes
         */
        ret = DPS_CountVectorAdd(node->interests, sub->bf);
        if (ret == DPS_OK) {
            ret = DPS_CountVectorAdd(node->needs, sub->needs);
        }
        if (ret == DPS_OK) {
            ret = FloodSubscriptions(node, NULL);
        }
    }
    return ret;
}

DPS_Status DPS_SubscribeCancel(DPS_Node* node, DPS_Subscription* subscription)
{
    DPS_Status ret;
    DPS_Subscription* sub;
    DPS_Subscription* prev = NULL;

    if (!node || !subscription) {
        return DPS_ERR_NULL;
    }
    sub = node->subscriptions;
    while (sub) {
        if (sub == subscription) {
            break;
        }
        prev = sub;
        sub = sub->next;
    }
    if (!sub) {
        return DPS_ERR_MISSING;
    }
    if (prev) {
        prev->next = sub->next;
    } else {
        node->subscriptions = sub->next;
    }
    DPS_DBGPRINT("Unsubscribing from %lu topics\n", sub->numTopics);
    DumpTopics(sub->topics, sub->numTopics);
    /*
     * TODO - optimization - check for no changes
     */
    ret = DPS_CountVectorDel(node->interests, sub->bf);
    if (ret == DPS_OK) {
        ret = DPS_CountVectorDel(node->needs, sub->needs);
    }
    if (ret == DPS_OK) {
        ret = FloodSubscriptions(node, NULL);
    }
    FreeSubscription(sub);
    return ret;
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
