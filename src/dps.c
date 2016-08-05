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


static const char DPS_SubscriptionURI[] = "dps";

typedef struct _RemoteNode {
    struct sockaddr_storage addr;
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
    DPS_MatchHandler handler;       /* Callback function to be called for a matching publication */
    DPS_Subscription* next;
    size_t numTopics;               /* Number of subscription topics */
    char* topics[1];                /* Subscription topics */
} DPS_Subscription;


#define PUB_FLAG_PUBLISH  (0x01)
#define PUB_FLAG_RETAINED (0x02)
#define PUB_FLAG_EXPIRED  (0x04)

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
    uint8_t flags;
    int16_t ttl;                    /* Remaining time-to-live in seconds */
    uint32_t serialNumber;          /* Serial number for this publication */
    uint8_t* payload;
    size_t len;
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

    DPS_CountVector* interests;           /* Tracks all interests for this node */
    DPS_CountVector* needs;               /* Tracks all needs for this node */

    DPS_History history;                  /* History of recently sent publications */
   
    DPS_Publication* publications;        /* Linked list of local and retained publications */
    DPS_Subscription* subscriptions;      /* Linked list of local subscriptions */

    DPS_MulticastReceiver* mcastReceiver;
    DPS_MulticastSender* mcastSender;

    DPS_NetListener* netListener;         /* TCP listener */

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

#define RemoteNodeAddrText(n)  DPS_NetAddrText((struct sockaddr*)(&(n)->addr))

static void CopySockaddr(struct sockaddr_storage* dest, struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET6) {
        memcpy(dest, addr, sizeof(struct sockaddr_in6));
    } else {
        memcpy(dest, addr, sizeof(struct sockaddr_in));
    }
}

static uint16_t GetPortNumber(struct sockaddr* addr)
{
    uint16_t port;
    if (addr->sa_family == AF_INET6) {
        port = ((struct sockaddr_in6*)addr)->sin6_port;
    } else {
        port = ((struct sockaddr_in*)addr)->sin_port;
    }
    return ntohs(port);
}

static struct sockaddr* AddrSetPort(struct sockaddr_storage* dest, const struct sockaddr* addr, uint16_t port)
{
    port = htons(port);
    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)dest;
        memcpy(ip6, addr, sizeof(*ip6));
        ip6->sin6_port = port;
    } else {
        struct sockaddr_in* ip4 = (struct sockaddr_in*)dest;
        memcpy(ip4, addr, sizeof(*ip4));
        ip4->sin_port = port;
    }
    return (struct sockaddr*)dest;
}

static int SameAddr(struct sockaddr_storage* addr, const struct sockaddr* b)
{
    struct sockaddr* a = (struct sockaddr*)addr;

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

    DPS_DBGPRINT("UpdateOutboundInterests: %s %s\n", RemoteNodeAddrText(destNode), *updates ? "Updates" : "No Change");
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
static DPS_Status AddRemoteNode(DPS_Node* node, struct sockaddr* addr, RemoteNode** remoteOut)
{
    RemoteNode* remote = LookupRemoteNode(node, addr);
    if (remote) {
        *remoteOut = remote;
        return DPS_ERR_EXISTS;
    }
    remote = calloc(1, sizeof(RemoteNode));
    if (!remote) {
        return DPS_ERR_RESOURCES;
    }
    DPS_DBGPRINT("Adding new remote node %s\n", DPS_NetAddrText(addr));
    CopySockaddr(&remote->addr, addr);
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
         * When a ttl expires retained publications are freed, local publications are disabled
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

static DPS_Status RetainPublication(DPS_Node* node, DPS_Publication* tmpPub)
{
    DPS_Status ret = DPS_OK;
    DPS_Publication* prev = NULL;
    DPS_Publication* pub;

    DPS_DBGTRACE();

    /*
     * Removed any stale retained pubs
     */
    LazyCheckTTLs(node);
    /*
     * Check if this is an update to an existing retained publication
     */
    for (pub = node->publications; pub; pub = pub->next) {
        if ((pub->flags & PUB_FLAG_RETAINED) && (memcmp(&pub->pubId, &tmpPub->pubId, sizeof(DPS_UUID) == 0))) {
            break;
        }
        prev = pub;
    }
    if (pub) {
        /*
         * The bit vector of a retained publication cannot change
         */
        if (!DPS_BitVectorEquals(tmpPub->bf, pub->bf)) {
            DPS_ERRPRINT("Inconsisten bit vector in retained pub");
            return DPS_ERR_INVALID;
        }
        /*
         *
         */
        if (tmpPub->serialNumber <= pub->serialNumber) {
            DPS_ERRPRINT("Publication is stale");
            return DPS_ERR_INVALID;
        }
        /*
         * Existing payload if present must be freed
         */
        if (pub->payload) {
            free(pub->payload);
            pub->payload = NULL;
        }
        /*
         * The bit vector will be replace below
         */
        DPS_BitVectorFree(pub->bf);
        pub->bf = NULL;
    } else {
        if (tmpPub->ttl < 0) {
            /*
             * Unexpected but harmless
             */
            DPS_BitVectorFree(tmpPub->bf);
            return DPS_OK;
        }
        pub = calloc(1, sizeof(DPS_Publication));
        if (!pub) {
            return DPS_ERR_RESOURCES;
        }
    }
    /*
     * Negative TTL means delete the retained publication
     */
    if (tmpPub->ttl < 0) {
        DPS_DBGPRINT("Explictly expiringin pub %s\n", DPS_UUIDToString(&tmpPub->pubId));
        FreePublication(node, pub);
        DPS_BitVectorFree(tmpPub->bf);
        return DPS_OK;
    }
    DPS_DBGPRINT("Retaining pub %s\n", DPS_UUIDToString(&tmpPub->pubId));
    pub->ttl = tmpPub->ttl;
    pub->flags = (PUB_FLAG_RETAINED | PUB_FLAG_PUBLISH);
    pub->pubId = tmpPub->pubId;
    pub->serialNumber = tmpPub->serialNumber;
    pub->bf = tmpPub->bf;
    pub->len = tmpPub->len;
    if (pub->len) {
        pub->payload = malloc(pub->len);
        if (!pub->payload) {
            free(pub);
            return DPS_ERR_RESOURCES;
        }
        memcpy(pub->payload, tmpPub->payload, pub->len);
    }
    pub->next = node->publications;
    node->publications = pub;
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

static DPS_Status CloneBufs(uv_buf_t* dest, uv_buf_t* src, size_t numBufs)
{
    size_t i;

    for (i = 0; i < numBufs; ++i, ++src) {
        dest[i].base = malloc(src->len);
        if (!dest[i].base) {
            FreeBufs(dest, i - 1);
            return DPS_ERR_RESOURCES;
        }
        memcpy(dest[i].base, src->base, src->len);
        dest[i].len = src->len;
    }
    return DPS_ERR_OK;
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
 * Push a publication to a remote node
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
static DPS_Status PushPublication(DPS_Node* node, DPS_Publication* pub, struct sockaddr* destAddr)
{
    DPS_Status ret;
    DPS_Buffer payload;
    uv_buf_t bufs[3];
    CoAP_Option opts[1];
    int protocol;

    DPS_DBGTRACE();

    if (destAddr) {
        DPS_DBGPRINT("PushPublication to %s\n", DPS_NetAddrText(destAddr));
        protocol = COAP_OVER_TCP;
    } else {
        DPS_DBGPRINT("PushPublication as multicast\n");
        protocol = COAP_OVER_UDP;
    }
    ret = DPS_BufferInit(&payload, NULL, 32 + DPS_BitVectorSerializeMaxSize(pub->bf) + pub->len);
    if (ret != DPS_OK) {
        return DPS_OK;
    }
    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = DPS_SubscriptionURI;
    opts[0].len = sizeof(DPS_SubscriptionURI);
    /*
     * Write the listening port
     */
    CBOR_EncodeUint16(&payload, DPS_GetPortNumber(node));
    /*
     * Messages are only retained at the first hop.
     */
    if (pub->flags & PUB_FLAG_RETAINED) {
        CBOR_EncodeInt16(&payload, 0);
    } else if (pub->flags & PUB_FLAG_EXPIRED) {
        /*
         * Negative TTL indicates to subscriber that a previously retained publication has expired
         */
        CBOR_EncodeInt16(&payload, -1);
    } else {
        CBOR_EncodeInt16(&payload, pub->ttl);
    }
    CBOR_EncodeBytes(&payload, (uint8_t*)&pub->pubId, sizeof(pub->pubId));
    CBOR_EncodeUint(&payload, pub->serialNumber);
    ret = DPS_BitVectorSerialize(pub->bf, &payload);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, pub->payload, pub->len);
    }
    if (ret == DPS_OK) {
        ret = CoAP_Compose(protocol, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
    }
    if (ret == DPS_OK) {
        if (destAddr) {
            ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), destAddr, OnSendToComplete);
            if (ret != DPS_OK) {
                OnSendToComplete(node, destAddr, bufs, A_SIZEOF(bufs), ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs));
            FreeBufs(bufs, A_SIZEOF(bufs));
        }
    }
    return ret;
}

/*
 * Forward a publication to a specific subscriber or all matching subscribers
 */
static DPS_Status ForwardPubToSubs(DPS_Node* node, DPS_Publication* pub, RemoteNode* subNode, RemoteNode* pubNode)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = node->remoteNodes;
    DPS_Publication tmpPub = *pub;
    DPS_BitVector* provides;

    DPS_DBGTRACE();

    /*
     * Ignore entries that have not yet been published
     */
    if (!pub->flags & PUB_FLAG_PUBLISH) {
        return DPS_OK;
    }
    /*
     * Short circuit if there is nothing to publish
     */
    if (DPS_BitVectorIsClear(pub->bf)) {
        return DPS_OK;
    }

    tmpPub.bf = DPS_BitVectorAlloc();
    provides = DPS_BitVectorAllocFH();
    if (!tmpPub.bf || !provides) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    while (remote) {
        struct sockaddr* dest = (struct sockaddr*)&remote->addr;
        /*
         * May only be forwarding to one specific subscriber
         */
        if (subNode && remote != subNode) {
            remote = remote->next;
            continue;
        }
        /*
         * Ignore nodes that are not currently subscribers
         */
        if (!remote->inbound.interests) {
            remote = remote->next;
            continue;
        }
        /*
         * Don't send publication back to the publisher
         */
        if (pubNode && SameAddr(&pubNode->addr, dest)) {
            DPS_DBGPRINT("ForwardPubToSubs don't send pub back to publisher\n");
            remote = remote->next;
            continue;
        }
        /*
         * Filter the pub against the subscription
         */
        DPS_BitVectorIntersection(tmpPub.bf, pub->bf, remote->inbound.interests);
        DPS_BitVectorFuzzyHash(provides, tmpPub.bf);
        if (DPS_BitVectorIncludes(provides, remote->inbound.needs)) {
            DPS_DBGPRINT("Forwarded pub %d to %s\n", pub->serialNumber, DPS_NetAddrText(dest));
            ret = PushPublication(node, &tmpPub, dest);
        } else {
            DPS_DBGPRINT("Rejected pub %d for %s\n", pub->serialNumber, DPS_NetAddrText(dest));
        }
        if (ret != DPS_OK) {
            remote = DeleteRemoteNode(node, remote);
        } else {
            remote = remote->next;
        }
    }
    /*
     * We only need to expire a retained publication once.
     */
    if (pub->flags & PUB_FLAG_EXPIRED) {
        pub->flags = 0;
        pub->ttl = 0;
    }

Exit:

    DPS_BitVectorFree(provides);
    DPS_BitVectorFree(tmpPub.bf);
    return ret;
}

static DPS_Status DecodePublicationRequest(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr)
{
    DPS_Status ret;
    RemoteNode* pubNode;
    int noChange = DPS_FALSE;
    uint16_t port;
    struct sockaddr_storage senderAddr;
    DPS_Publication pub;
    DPS_UUID* pubId;
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
    if (DPS_PublicationIsStale(&node->history, &pub.pubId, pub.serialNumber)) {
        DPS_DBGPRINT("Publication is stale\n");
        return DPS_OK;
    }
    ret = AddRemoteNode(node, AddrSetPort(&senderAddr, addr, port), &pubNode);
    if (ret == DPS_ERR_EXISTS) {
        DPS_DBGPRINT("Updating existing node\n");
        ret = DPS_OK;
    }
    if (ret != DPS_OK) {
        return ret;
    }
    pub.bf = DPS_BitVectorAlloc();
    if (!pub.bf) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_BitVectorDeserialize(pub.bf, buffer);
    if (ret == DPS_OK) {
        ret = CBOR_DecodeBytes(buffer, &pub.payload, &pub.len);
    }
    if (ret == DPS_OK) {
        DPS_Subscription* sub;
        DPS_Subscription* next;
        /*
         * Check if there is a local subscription for this publication
         */
        for (sub = node->subscriptions; sub != NULL; sub = next) {
            /*
             * Ths current subscription might get freed by the handler so need to hold the next pointer here.
             */
            next = sub->next;
            if (DPS_BitVectorIncludes(pub.bf, sub->bf)) {
                DPS_DBGPRINT("Matched subscription\n");
                sub->handler(node, sub, (const char**)sub->topics, sub->numTopics, pub.payload, pub.len);
            }
        }
        DPS_AppendPubHistory(&node->history, &pub.pubId, pub.serialNumber);
        /*
         * Forward the publication to matching remote subscribers
         */
        pub.flags = PUB_FLAG_PUBLISH;
        ret = ForwardPubToSubs(node, &pub, NULL, pubNode);
        /*
         * Publications with a non-zero TTL will be retained until the TTL expires.
         */
        if (pub.ttl) {
            ret = RetainPublication(node, &pub);
            if (ret != DPS_OK) {
                DPS_BitVectorFree(pub.bf);
            }
        } else {
            DPS_BitVectorFree(pub.bf);
        }
    } else {
        DeleteRemoteNode(node, pubNode);
    }
    DPS_FreshenHistory(&node->history);
    return ret;
}

/*
 * Subscription request:
 *
 * COAP header
 * COAP URI PATH
 * Payload (CBOR encoded):
 *      Port number we are listening on
 *      Our IPv6 address (filled in later)
 *      Serialized bloom filter
 */
static DPS_Status ComposeSubscriptionRequest(DPS_Node* node, RemoteNode* remote, int protocol, uv_buf_t* bufs, size_t numBufs)
{
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
    opts[0].val = DPS_SubscriptionURI;
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
        ret = CoAP_Compose(protocol, bufs, numBufs, COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), &payload);
    }
    if (ret != DPS_OK) {
        free(payload.base);
    }
    return ret;
}

static DPS_Status SendSubscriptions(DPS_Node* node, RemoteNode* remote)
{
    uv_buf_t bufs[3];
    DPS_Status ret;

    ret = ComposeSubscriptionRequest(node, remote, COAP_OVER_TCP, bufs, A_SIZEOF(bufs));
    if (ret == DPS_OK) {
        ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr, OnSendToComplete);
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
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
     * Forward subscription to all remote nodes witn interestss
     */
    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        int updates;
        uv_buf_t bufs[3];

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
        ret = ComposeSubscriptionRequest(node, remote, COAP_OVER_TCP, bufs, A_SIZEOF(bufs));
        if (ret != DPS_OK) {
            break;
        }
        ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr, OnSendToComplete);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
            OnSendToComplete(node, (struct sockaddr*)&remote->addr, bufs, A_SIZEOF(bufs), ret);
            /*
             * Keep trying the other nodes
             */
            ret = DPS_OK;
        }
    }
    return ret;
}

/*
 * Update the interests for a remote node
 */
static DPS_Status UpdateInboundInterests(DPS_Node* node, RemoteNode* remote, DPS_BitVector* interests, DPS_BitVector* needs)
{
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
 * A subscription filter
 */
static DPS_Status DecodeSubscriptionRequest(DPS_Node* node, DPS_Buffer* buffer, const struct sockaddr* addr)
{
    DPS_Status ret;
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    struct sockaddr_storage senderAddr;
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
    ret = AddRemoteNode(node, AddrSetPort(&senderAddr, addr, port), &remote);
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
        uint32_t elapsed;
        DPS_Publication* pub;
        DPS_Publication* next;
        /*
         * Determine what if anything has changed
         */
        ret = FloodSubscriptions(node, isNew ? remote : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("FloodSubscriptions failed %s\n", DPS_ErrTxt(ret));
        }
        LazyCheckTTLs(node);
        /*
         * Check if any local or retained publications need to be forwarded to this subscriber
         */
        for (pub = node->publications; pub != NULL; pub = pub->next) {
            /*
             * Save next in case pub is expired
             */
            next = pub->next;
            ret = ForwardPubToSubs(node, pub, isNew ? remote : NULL, NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("ForwardPubToSubs failed %s\n", DPS_ErrTxt(ret));
            }
            /*
             * Could be a network send error
             */
            ret = DPS_OK;
        }
    }
    /*
     * We don't need to keep a remote node that has no inbound interests
     */
    if (DPS_BitVectorIsClear(remote->inbound.interests)) {
        DPS_DBGPRINT("Remote node has no interests - deleting\n", RemoteNodeAddrText(remote));
        DeleteRemoteNode(node, remote);
    }
    return ret;
}

static void DecodeRequest(DPS_Node* node, CoAP_Parsed* coap, DPS_Buffer* payload, const struct sockaddr* sender)
{
    DPS_Status ret;
    int gotURI = 0;
    size_t i;

    for (i = 0; i < coap->numOpts; ++i) {
        if (coap->opts[i].id == COAP_OPT_URI_PATH) {
            if (strncmp(coap->opts[i].val, DPS_SubscriptionURI, coap->opts[i].len) == 0) {
                gotURI = 1;
                break;
            }
        }
    }
    if (!gotURI) {
        DPS_DBGPRINT("CoAP packet is not for us\n");
        return;
    }
    if (coap->code == COAP_CODE(COAP_REQUEST, COAP_GET)) {
        /*
         * This should be a subscription request
         */
        ret = DecodeSubscriptionRequest(node, payload, sender);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscriptionRequest returned %s\n", DPS_ErrTxt(ret));
        }
    } else if (coap->code == COAP_CODE(COAP_REQUEST, COAP_PUT)) {
        /*
         * This should be a publication
         */
        DPS_DBGPRINT("Received publication via %s\n", DPS_NetAddrText(sender));
        ret = DecodePublicationRequest(node, payload, sender);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublicationRequest returned %s\n", DPS_ErrTxt(ret));
        }
    } else {
        DPS_ERRPRINT("Ignoring unexpected CoAP packet: code= %d\n", coap->code);
    }
}

/*
 * Using CoAP packetization for receiving multicast subscription requests
 */
static ssize_t OnMulticastReceive(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    DPS_Status dpsRet;
    ssize_t ret;
    CoAP_Parsed coap;
    int subReq = 0;
    size_t i;

    DPS_DBGTRACE();

    if (!data || !len) {
        return 0;
    }
    ret = CoAP_Parse(COAP_OVER_UDP, data, len, &coap, &payload);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Discarding garbage multicast packet len=%d\n", len);
        return 0;
    }
    /*
     * Multicast packets must be non-confirmable
     */
    if (coap.type != COAP_TYPE_NON_CONFIRMABLE) {
        DPS_ERRPRINT("Discarding packet within bad type=%d\n", coap.type);
        return 0;
    }
    DecodeRequest(node, &coap, &payload, addr);
    CoAP_Free(&coap);
    return len;
}

static ssize_t OnNetReceive(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    size_t i;
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
    DecodeRequest(node, &coap, &payload, addr);
    CoAP_Free(&coap);
    return 0;
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
    if (!node->interests) {
        free(node);
        return NULL;
    }
    node->needs = DPS_CountVectorAllocFH();
    if (!node->needs) {
        free(node->interests);
        free(node);
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
        return;
    }

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
    DPS_HistoryFree(&node->history);

    free(node);
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

DPS_Status DPS_CreatePublication(DPS_Node* node, char* const* topics, size_t numTopics, DPS_Publication** publication)
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
    DPS_DBGPRINT("Creating publication with %d topics\n", numTopics);
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
    size_t i;
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
    ++pub->serialNumber;

    if (pub->ttl && !ttl) {
        pub->flags |= PUB_FLAG_EXPIRED;
    }
    pub->ttl = ttl;
    if (ttl && !node->ttlBasis) {
        UpdateTTLBasis(node);
    }
    if (node->mcastSender) {
        ret = PushPublication(node, pub, NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("PushPublication (multicast) returned %s\n", DPS_ErrTxt(ret));
        }
    }
    ret = ForwardPubToSubs(node, pub, NULL, NULL);

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
    uv_buf_t bufs[3];
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
    ret = ComposeSubscriptionRequest(node, remote, COAP_OVER_TCP, bufs, A_SIZEOF(bufs));
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), (struct sockaddr*)&remote->addr, OnSendToComplete);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
        OnSendToComplete(node, (struct sockaddr*)&remote->addr, bufs, A_SIZEOF(bufs), ret);
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
    ret = AddRemoteNode(node, (struct sockaddr*)&addr->ip6, &remote);
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
    RemoteNode* remote = LookupRemoteNode(node, (struct sockaddr*)&addr->ip6);
    if (remote) {
        DeleteRemoteNode(node, remote);
        return DPS_OK;
    } else {
        return DPS_ERR_MISSING;
    }
}

DPS_Status DPS_Subscribe(DPS_Node* node, char* const* topics, size_t numTopics, DPS_MatchHandler handler, DPS_Subscription** subscription)
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
        DPS_DBGPRINT("Subscribing to %d topics\n", numTopics);
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
    DPS_DBGPRINT("Unsubscribing from %d topics\n", sub->numTopics);
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
            addr->ip6 = *ip6;
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
