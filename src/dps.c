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
#include <coap.h>
#include <cbor.h>
#include <network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#define _MIN_(x, y)  (((x) < (y)) ? (x) : (y))


static const char DPS_SubscriptionURI[] = "dps";

typedef struct _SubList {
    DPS_NodeAddress nodeAddr;
    DPS_BitVector* needs;           /* Subscription needs */
    DPS_BitVector* interests;       /* The bit vector for the interests of a set of remote subscribers */
    struct _SubList* next;
} SubList;

typedef struct _PubList {
    uint8_t match;                  /* Match flag for use in loops */
    uint64_t revision;              /* Revision number for this publisher */
    DPS_NodeAddress nodeAddr;       /* Address for the remote node */
    struct _PubList* next;
} PubList;

/*
 * Struct to hold the state of a local subscription. We hold the topics so we can provide return the topic list when we
 * get a match. We compute the filter so we can forward to downstream subscribers.
 */
typedef struct _DPS_Subscription {
    DPS_BitVector* needs;           /* Subscription needs */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this subscription */
    DPS_MatchHandler handler;       /* Callback function to be called for a matching publication */
    DPS_Subscription* next;
    size_t numTopics;               /* Number of subscription topics */
    char* topics[1];                /* Subscription topics */
} DPS_Subscription;

typedef struct _DPS_Publication {
    uint8_t* data;
    size_t len;
    uint8_t flags;                  /* Additional information about the publication */
    uint64_t revision;              /* Revision number for this publication */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Publication* next;
} DPS_Publication;

typedef struct _DPS_Node {

    char separators[13];                  /* List of separator characters */

    uv_loop_t* loop;                      /* uv lib event loop */
    uv_idle_t idler;                      /* for doing background work */

    uint64_t revision;                    /* Revision number for this node */

    PubList* remotePubs;                  /* Linked list of remote publishers */
    SubList* remoteSubs;                  /* Linked list of remote subscribers */

    DPS_BitVector* interests;             /* Rolled-up union of subscription interests for this node */
    DPS_BitVector* needs;                 /* Rolled-up intersection of subscription needs */

    DPS_Publication* localPubs;           /* Linked list of local publications */
    DPS_Subscription* localSubs;          /* Linked list of local subscriptions */

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

static struct sockaddr* ToSockaddr(const DPS_NodeAddress* addr, struct sockaddr_in6* ip6)
{
    memset(ip6, 0, sizeof(*ip6));
    ip6->sin6_family = AF_INET6;
    ip6->sin6_scope_id = 2;
    ip6->sin6_port = htons(addr->port);
    memcpy(&ip6->sin6_addr, addr->addr, 16);
    return (struct sockaddr*)ip6;
}

static DPS_NodeAddress* ToNodeAddr(const struct sockaddr* addr, DPS_NodeAddress* nodeAddr)
{
    const struct sockaddr_in6* ip6 = (const struct sockaddr_in6*)addr;
    if (ip6->sin6_family != AF_INET6) {
        return NULL;
    }
    nodeAddr->port = ntohs(ip6->sin6_port);
    memcpy(nodeAddr->addr, &ip6->sin6_addr, 16);
    return nodeAddr;
}

const char* DPS_NodeAddressText(const DPS_NodeAddress* addr)
{
    if (addr) {
        static char txt[INET6_ADDRSTRLEN + 8];
        struct sockaddr_in6 ip6;
        sprintf(txt, "%s/%d", DPS_NetAddrText(ToSockaddr(addr, &ip6)), addr->port);
        return txt;
    } else {
        return "NULL";
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

static DPS_Status DecodeAddr(DPS_Buffer* buffer, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    uint64_t n;
    size_t l;
    uint8_t* p;

    /*
     * Get the subscribers address and port
     */
    ret = CBOR_DecodeUint(buffer, &n);
    if (ret != DPS_OK) {
        return ret;
    }
    if (n > UINT16_MAX) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeBytes(buffer, &p, &l);
    if (ret != DPS_OK) {
        return ret;
    }
    if (l != 16) {
        return DPS_ERR_INVALID;
    }
    memcpy(addr->addr, p, 16);
    addr->port = n;
    DPS_DBGPRINT("DecodeAddr %s\n", DPS_NodeAddressText(addr));
    return DPS_OK;
}

static int SameAddr(DPS_NodeAddress* a, DPS_NodeAddress* b)
{
    return a->port == b->port && memcmp(a->addr, b->addr, 16) == 0;
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

static SubList* FreeRemoteSub(SubList* sub)
{
    SubList* next = sub->next;
    DPS_BitVectorFree(sub->interests);
    DPS_BitVectorFree(sub->needs);
    free(sub);
    return next;
}

static PubList* FreeRemotePub(PubList* pub)
{
    PubList* next = pub->next;
    free(pub);
    return next;
}

static DPS_Publication* FreePublication(DPS_Publication* pub)
{
    DPS_Publication* next = pub->next;
    free(pub);
    return next;
}

/*
 *
 */
static DPS_Status RefreshSubscriptionInterests(DPS_Node* node, DPS_NodeAddress* addr, DPS_BitVector* interests, DPS_BitVector* needs, SubList** newSub, int* noChange)
{
    DPS_BitVector* newInterests;
    DPS_Subscription* localSub;
    SubList* sub = NULL;

    DPS_DBGTRACE();

    *noChange = DPS_FALSE;
    /*
     * Is this an update from a known subscriber?
     */
    if (addr) {
        assert(interests);
        for (sub = node->remoteSubs; sub != NULL; sub = sub->next) {
            if (SameAddr(&sub->nodeAddr, addr)) {
                break;
            }
        }
        if (sub) {
            DPS_BitVectorFree(sub->interests);
            DPS_BitVectorFree(sub->needs);
            sub->interests = interests;
            sub->needs = needs;
            *newSub = NULL;
        } else {
            sub = malloc(sizeof(SubList));
            if (!sub) {
                return DPS_ERR_RESOURCES;
            }
            DPS_DBGPRINT("Adding new remote subscriber %s\n", DPS_NodeAddressText(addr));
            sub->nodeAddr = *addr;
            sub->interests = interests;
            sub->needs = needs;
            /*
             * Link in new subscriber
             */
            sub->next = node->remoteSubs;
            node->remoteSubs = sub;
            *newSub = sub;
        }
    } else {
        assert(!interests && !needs && !newSub);
    }
    newInterests = DPS_BitVectorAlloc();
    if (!newInterests) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Prepare needs for rebuilding intersection
     *
     * TODO - do we need to check the needs for changes too?
     */
    DPS_BitVectorFill(node->needs);
    /*
     * Compute the union of the remote and local subscription filters this represents the interests 
     * of this set of subscriptions.
     */
    for (sub = node->remoteSubs; sub != NULL; sub = sub->next) {
        DPS_BitVectorUnion(newInterests, sub->interests);
        DPS_BitVectorIntersection(node->needs, node->needs, sub->needs);
    }
    for (localSub = node->localSubs; localSub != NULL; localSub = localSub->next) {
        DPS_BitVectorUnion(newInterests, localSub->bf);
        DPS_BitVectorIntersection(node->needs, node->needs, localSub->needs);
    }
    if (DPS_BitVectorEquals(node->interests, newInterests)) {
        DPS_BitVectorFree(newInterests);
        *noChange = DPS_TRUE;
    } else {
        DPS_BitVectorFree(node->interests);
        node->interests  = newInterests;
    }
    DPS_DBGPRINT("RefreshSubscriptionInterests: %s\n", *noChange ? "No Change" : "Changes");
    return DPS_OK;
}

static void DeleteRemoteSubscriber(DPS_Node* node, DPS_NodeAddress* addr)
{
    SubList* sub = node->remoteSubs;
    SubList* prev = NULL;

    DPS_DBGTRACE();
    for (sub = node->remoteSubs; sub != NULL; prev = sub, sub = sub->next) {
        if (SameAddr(&sub->nodeAddr, addr)) {
            SubList* next = FreeRemoteSub(sub);
            if (prev) {
                prev->next = next;
            } else {
                node->remoteSubs = next;
            }
            break;
        }
    }
}

static PubList* LookupRemotePublisher(DPS_Node* node, DPS_NodeAddress* addr)
{
    PubList* pub;

    for (pub = node->remotePubs; pub != NULL; pub = pub->next) {
        if (SameAddr(&pub->nodeAddr, addr)) {
            return pub;
        }
    }
    return NULL;
}

/*
 * Add a remote publisher or return an existing one
 */
static DPS_Status AddRemotePublisher(DPS_Node* node, DPS_NodeAddress* addr, PubList** pubOut)
{
    PubList* pub = LookupRemotePublisher(node, addr);
    if (pub) {
        *pubOut = pub;
        return DPS_ERR_EXISTS;
    }
    pub = malloc(sizeof(PubList));
    if (!pub) {
        return DPS_ERR_RESOURCES;
    }
    memset(pub, 0, sizeof(PubList));
    pub->nodeAddr = *addr;
    DPS_DBGPRINT("Adding new publisher\n");
    pub->next = node->remotePubs;
    node->remotePubs = pub;
    *pubOut = pub;
    return DPS_OK;
}

static void DeleteRemotePublisher(DPS_Node* node, PubList* pub)
{
    if (pub == node->remotePubs) {
        node->remotePubs = pub->next;
    } else {
        PubList* prev = node->remotePubs;
        while (prev->next != pub) {
            prev = prev->next;
        }
        assert(prev);
        prev->next = pub->next;
    }
    free(pub);
}

static DPS_Status PersistPublication(DPS_Node* node, DPS_Publication* tmpPub)
{
    DPS_Status ret = DPS_OK;
    DPS_Publication* pub;

    DPS_DBGTRACE();

    pub = malloc(sizeof(DPS_Publication));
    if (!pub) {
        return DPS_ERR_RESOURCES;
    }
    pub->next = NULL;
    pub->flags = tmpPub->flags & ~DPS_PUB_FLAG_PERSIST;
    pub->revision = tmpPub->revision;
    pub->bf = tmpPub->bf;
    pub->len = tmpPub->len;
    if (pub->len) {
        pub->data = malloc(pub->len);
        if (!pub->data) {
            free(pub);
            return DPS_ERR_RESOURCES;
        }
        memcpy(pub->data, tmpPub->data, pub->len);
    }
    pub->next = node->localPubs;
    node->localPubs = pub;
    return DPS_OK;
}

static void FreeBufs(uv_buf_t* bufs, size_t numBufs)
{
    size_t i;
    for (i = 0; i < numBufs; ++i) {
        free(bufs[i].base);
    }
}

static void OnSendToPubComplete(DPS_Node* node, const struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        DPS_NodeAddress nodeAddr;
        PubList* pub = LookupRemotePublisher(node, ToNodeAddr(addr, &nodeAddr));
        DPS_ERRPRINT("OnSendToPubComplete %s\n", DPS_ErrTxt(status));
        if (pub) {
            DPS_ERRPRINT("Removing publisher %s\n", DPS_NodeAddressText(&nodeAddr));
            DeleteRemotePublisher(node, pub);
        }
    }
    FreeBufs(bufs, numBufs);
}

static void OnSendToSubComplete(DPS_Node* node, const struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    if (status != DPS_OK) {
        DPS_NodeAddress nodeAddr;
        DPS_ERRPRINT("OnSendToSubComplete %s\n", DPS_ErrTxt(status));
        DeleteRemoteSubscriber(node, ToNodeAddr(addr, &nodeAddr));
        DPS_ERRPRINT("Removed subscriber %s\n", DPS_NodeAddressText(&nodeAddr));
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
static DPS_Status PushPublication(DPS_Node* node, DPS_Publication* pub, DPS_NodeAddress* pubAddr, DPS_NodeAddress* destAddr)
{
    DPS_Status ret;
    DPS_Buffer payload;
    uint8_t* addrPtr = NULL;
    uv_buf_t bufs[3];
    CoAP_Option opts[1];
    int protocol;

    DPS_DBGTRACE();

    /*
     * May not be anything to publish
     */
    if (DPS_BitVectorIsClear(pub->bf)) {
        DPS_DBGPRINT("PushPublication nothing to publish\n");
        return DPS_OK;
    }
    if (destAddr) {
        DPS_DBGPRINT("PushPublication to %s\n", DPS_NodeAddressText(destAddr));
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

    if (pubAddr) {
        /*
         * Send the address of the publisher
         */
        CBOR_EncodeUint(&payload, pubAddr->port);
        CBOR_EncodeBytes(&payload, pubAddr->addr, 16);
    } else {
        /*
         * Write listening port and reserve space for the address to be filled in later.
         */
        CBOR_EncodeUint(&payload, DPS_NetGetListenerPort(node->netListener));
        CBOR_ReserveBytes(&payload, 16, &addrPtr);
    }
    CBOR_EncodeUint8(&payload, pub->flags);
    CBOR_EncodeUint(&payload, pub->revision);
    ret = DPS_BitVectorSerialize(pub->bf, &payload);
    if (ret == DPS_OK) {
        CBOR_EncodeBytes(&payload, pub->data, pub->len);
    }
    if (ret == DPS_OK) {
        ret = CoAP_Compose(protocol, bufs, A_SIZEOF(bufs), COAP_CODE(COAP_REQUEST, COAP_PUT), opts, A_SIZEOF(opts), &payload);
    }
    if (ret == DPS_OK) {
        if (destAddr) {
            struct sockaddr_in6 ip6;
            ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), addrPtr, ToSockaddr(destAddr, &ip6), OnSendToSubComplete);
            if (ret != DPS_OK) {
                OnSendToSubComplete(node, (const struct sockaddr*)&ip6, bufs, A_SIZEOF(bufs), ret);
            }
        } else {
            ret = DPS_MulticastSend(node->mcastSender, bufs, A_SIZEOF(bufs), addrPtr);
            FreeBufs(bufs, A_SIZEOF(bufs));
        }
    }
}

/*
 * Forward a publication to matching subscribers
 */
static DPS_Status ForwardPubToSubs(DPS_Node* node, DPS_Publication* pub, DPS_NodeAddress* pubAddr, SubList* newSub)
{
    DPS_Status ret = DPS_OK;
    SubList* sub = node->remoteSubs;
    DPS_Publication tmpPub = *pub;
    DPS_BitVector* provides;

    DPS_DBGTRACE();

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
    while (sub) {
        if (newSub && sub != newSub) {
            sub = sub->next;
            continue;
        }
        /*
         * Filter the pub against the subscription
         */
        DPS_BitVectorIntersection(tmpPub.bf, pub->bf, sub->interests);
        DPS_BitVectorFuzzyHash(provides, tmpPub.bf);
        if (DPS_BitVectorIncludes(provides, sub->needs)) {
            DPS_DBGPRINT("Forwarded pub %d to %s\n", pub->revision, DPS_NodeAddressText(&sub->nodeAddr));
            ret = PushPublication(node, &tmpPub, pubAddr, &sub->nodeAddr);
        } else {
            DPS_DBGPRINT("Rejected pub %d for %s\n", pub->revision, DPS_NodeAddressText(&sub->nodeAddr));
        }
        if (ret != DPS_OK) {
            if (sub == node->remoteSubs) {
                node->remoteSubs = sub->next;
            }
            sub = FreeRemoteSub(sub);
        } else {
            sub = sub->next;
        }
    }

Exit:

    DPS_BitVectorFree(provides);
    DPS_BitVectorFree(tmpPub.bf);
    return ret;
}

static DPS_Status DecodePublicationRequest(DPS_Node* node, DPS_Buffer* buffer)
{
    DPS_Status ret;
    PubList* publisher;
    uint64_t revision;
    uint8_t flags;
    int noChange = DPS_FALSE;
    DPS_NodeAddress addr;
    DPS_Publication pub;
    size_t len;

    DPS_DBGTRACE();

    ret = DecodeAddr(buffer, &addr);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeUint8(buffer, &flags);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeUint(buffer, &revision);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = AddRemotePublisher(node, &addr, &publisher);
    if (ret == DPS_ERR_EXISTS) {
        if (revision <= publisher->revision) {
            DPS_DBGPRINT("Publication is stale\n");
            return DPS_OK;
        }
        DPS_DBGPRINT("Updating existing publisher\n");
        ret = DPS_OK;
    }
    if (ret != DPS_OK) {
        return ret;
    }
    publisher->revision = revision;
    pub.revision = revision;
    pub.flags = DPS_PUB_FLAGS_NONE;
    pub.bf = DPS_BitVectorAlloc();
    if (!pub.bf) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_BitVectorDeserialize(pub.bf, buffer);
    if (ret == DPS_OK) {
        ret = CBOR_DecodeBytes(buffer, &pub.data, &pub.len);
    }
    if (ret == DPS_OK) {
        DPS_Subscription* sub;
        DPS_Subscription* next;
        /*
         * Check if there is a local subscription for this publication
         */
        for (sub = node->localSubs; sub != NULL; sub = next) {
            /*
             * Ths current subscription might get freed by the handler so need to hold the next pointer here.
             */
            next = sub->next;
            if (DPS_BitVectorIncludes(pub.bf, sub->bf)) {
                DPS_DBGPRINT("Matched subscription\n");
                sub->handler(node, sub, (const char**)sub->topics, sub->numTopics, &publisher->nodeAddr, pub.data, pub.len);
            }
        }
        /*
         * Forward the publication to matching remote subscribers
         */
        ret = ForwardPubToSubs(node, &pub, &addr, NULL);
        /*
         * Check if the publication should persist
         */
        if (flags & DPS_PUB_FLAG_PERSIST) {
            ret = PersistPublication(node, &pub);
            if (ret != DPS_OK) {
                DPS_BitVectorFree(pub.bf);
            }
        } else {
            DPS_BitVectorFree(pub.bf);
        }
    } else {
        DeleteRemotePublisher(node, publisher);
    }
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
static DPS_Status ComposeSubscriptionRequest(DPS_Node* node, int protocol, uv_buf_t* bufs, size_t numBufs, uint8_t** ip6address)
{
    DPS_Status ret;
    CoAP_Option opts[1];
    uint16_t port;
    DPS_Buffer payload;
    size_t allocSize = DPS_BitVectorSerializeMaxSize(node->needs) + DPS_BitVectorSerializeMaxSize(node->interests) + 32;

    if (!node->netListener) {
        return DPS_ERR_NETWORK;
    }
    port = DPS_NetGetListenerPort(node->netListener);

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = DPS_SubscriptionURI;
    opts[0].len = sizeof(DPS_SubscriptionURI);

    ret = DPS_BufferInit(&payload, NULL, allocSize);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Write listening port and reserve space for the address to be filled in later.
     */
    CBOR_EncodeUint(&payload, port);
    CBOR_ReserveBytes(&payload, 16, ip6address);

    ret = DPS_BitVectorSerialize(node->needs, &payload);
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(node->interests, &payload);
    }
    if (ret == DPS_OK) {
        ret = CoAP_Compose(protocol, bufs, numBufs, COAP_CODE(COAP_REQUEST, COAP_GET), opts, A_SIZEOF(opts), &payload);
    }
    if (ret != DPS_OK) {
        free(payload.base);
    }
    return ret;
}

static DPS_Status SendSubscription(DPS_Node* node, PubList* pub)
{
    DPS_Status ret;
    struct sockaddr_in6 ip6;
    uint8_t* addrPtr;
    uv_buf_t bufs[3];

    /*
     * Send subscriptions to a specific publisher
     */
    ret = ComposeSubscriptionRequest(node, COAP_OVER_TCP, bufs, A_SIZEOF(bufs), &addrPtr);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), addrPtr, ToSockaddr(&pub->nodeAddr, &ip6), OnSendToPubComplete);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
        OnSendToPubComplete(node, (const struct sockaddr*)&ip6, bufs, A_SIZEOF(bufs), ret);
    }
    return ret;
}

static DPS_Status FloodSubscriptions(DPS_Node* node)
{
    DPS_Status ret;
    PubList* pub;
    struct sockaddr_in6 ip6;
    uint8_t* addrPtr;
    uv_buf_t bufs[3];
    int successes = 0;

    DPS_DBGTRACE();

    if (!node->remotePubs) {
        return DPS_OK;
    }
    /*
     * TODO - serialize the subscription once and memcpy for each publisher
     */
    for (pub = node->remotePubs; pub != NULL; pub = pub->next) {
        /*
         * Send subscription to all the downstream publishers we know about
         */
        ret = ComposeSubscriptionRequest(node, COAP_OVER_TCP, bufs, A_SIZEOF(bufs), &addrPtr);
        if (ret != DPS_OK) {
            break;
        }
        ret = DPS_NetSend(node, bufs, A_SIZEOF(bufs), addrPtr, ToSockaddr(&pub->nodeAddr, &ip6), OnSendToPubComplete);
        if (ret == DPS_OK) {
            ++successes;
        } else {
            DPS_ERRPRINT("Failed to send subscription request: ret=%d\n", ret);
            OnSendToPubComplete(node, (const struct sockaddr*)&ip6, bufs, A_SIZEOF(bufs), ret);
            ret = DPS_OK;
        }
    }
    /*
     * Only return an error if no requests were succesful
     */
    if (successes == 0) {
        ret = DPS_ERR_NETWORK;
    } else {
        ret = DPS_OK;
    }
    return ret;
}

/*
 * A subscription filter
 */
static DPS_Status DecodeSubscriptionRequest(DPS_Node* node, DPS_Buffer* buffer)
{
    DPS_Status ret;
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    DPS_NodeAddress addr;
    SubList* newSub;
    int noChange;

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
    ret = DecodeAddr(buffer, &addr);
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
    /*
     * Recompute the subscription filter and decide if it should to be forwarded to the publishers
     */
    ret = RefreshSubscriptionInterests(node, &addr, interests, needs, &newSub, &noChange);
    if (ret != DPS_OK) {
        DPS_BitVectorFree(interests);
        DPS_BitVectorFree(needs);
    } else {
        DPS_Publication* pub;
        if (!noChange) {
            /*
             * The interests changed so forward the update to the downstream publishers
             */
            ret = FloodSubscriptions(node);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("FloodSubscriptions failed %s\n", DPS_ErrTxt(ret));
            }
        }
        /*
         * Check if any local publication need to be forwarded to subscribers based on tbe updated interests
         *
         * TODO - only do this for subscribers that changed - we don't currently track this
         */
        for (pub = node->localPubs; pub != NULL; pub = pub->next) {
            ret = ForwardPubToSubs(node, pub, NULL, newSub);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("ForwardPubToSubsfailed %s\n", DPS_ErrTxt(ret));
            }
            /*
             * Could be a network send error
             */
            ret = DPS_OK;
        }
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
        ret = DecodeSubscriptionRequest(node, payload);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscriptionRequest returned %s\n", DPS_ErrTxt(ret));
        }
    } else if (coap->code == COAP_CODE(COAP_REQUEST, COAP_PUT)) {
        /*
         * This should be a publication
         */
        DPS_DBGPRINT("Received publication via %s\n", sender ? DPS_NetAddrText(sender) : "multicast");
        ret = DecodePublicationRequest(node, payload);
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
    DecodeRequest(node, &coap, &payload, NULL);
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

DPS_Node* DPS_InitNode(int mcastListen, int tcpPort, const char* separators)
{
    DPS_Status ret;
    DPS_Node* node = malloc(sizeof(DPS_Node));

    if (!node) {
        return NULL;
    }

    memset(node, 0, sizeof(*node));
    strncpy(node->separators, separators, sizeof(node->separators));
    node->loop = uv_default_loop();
    node->revision = (uv_hrtime() / 1000000) & 0xFFFFFFFF;

    /*
     * Initialize an idler to do background work
     */
    node->idler.data = node;
    uv_idle_init(node->loop, &node->idler);

    node->interests = DPS_BitVectorAlloc();
    if (!node->interests) {
        free(node);
        return NULL;
    }
    node->needs = DPS_BitVectorAllocFH();
    if (!node->needs) {
        free(node->interests);
        free(node);
        return NULL;
    }

    if (mcastListen) {
        node->mcastReceiver = DPS_MulticastStartReceive(node, OnMulticastReceive);
    }
    node->mcastSender = DPS_MulticastStartSend(node);
    node->netListener = DPS_NetStartListening(node, tcpPort, OnNetReceive);

    return node;
}

uv_loop_t* DPS_GetLoop(DPS_Node* node)
{
    return node->loop;
}

uint16_t DPS_GetPortNumber(DPS_Node* node)
{
    if (node && node->netListener) {
        DPS_NetGetListenerPort(node->netListener);
    } else {
        return 0;
    }
}

static void TerminateOnIdle(uv_idle_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;

    DPS_BitVectorFree(node->interests);
    DPS_BitVectorFree(node->needs);

    while (node->localPubs) {
        node->localPubs = FreePublication(node->localPubs);
    }
    while (node->localSubs) {
        node->localSubs = FreeSubscription(node->localSubs);
    }
    while (node->remoteSubs) {
        node->remoteSubs = FreeRemoteSub(node->remoteSubs);
    }
    while (node->remotePubs) {
        node->remotePubs = FreeRemotePub(node->remotePubs);
    }
    uv_idle_stop(handle);
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
    if (node->netListener) {
        DPS_NetStopListening(node->netListener);
    }
    uv_idle_start(&node->idler, TerminateOnIdle);
}

DPS_Status DPS_Publish(DPS_Node* node, char* const* topics, size_t numTopics, DPS_Publication** publication, void* data, size_t len, uint8_t flags)
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
    DPS_DBGPRINT("Publishing %d topics\n", numTopics);
    DumpTopics(topics, numTopics);
    /*
     * Create the publication
     */
    pub = malloc(sizeof(DPS_Publication));
    if (!pub) {
        return DPS_ERR_RESOURCES;
    }
    pub->next = NULL;
    pub->flags = flags;
    pub->revision = ++node->revision;
    pub->data = data;
    pub->len = len;
    pub->bf = DPS_BitVectorAlloc();
    if (!pub->bf) {
        free(pub);
        return DPS_ERR_RESOURCES;
    }
    for (i = 0; i < numTopics; ++i) {
        ret = DPS_AddTopic(pub->bf, topics[i], node->separators, DPS_Pub);
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret == DPS_OK) {
        ret = PushPublication(node, pub, NULL, NULL);
        ret = ForwardPubToSubs(node, pub, NULL, NULL);
    }
    if (ret == DPS_OK) {
        pub->next = node->localPubs;
        node->localPubs = pub;
        *publication = pub;
    } else {
        FreePublication(pub);
    }
    return ret;
}

DPS_Status DPS_PublishCancel(DPS_Node* node, DPS_Publication* pub, void** data)
{
    DPS_Publication* prev = NULL;
    DPS_Publication* list;

    DPS_DBGTRACE();
    if (!node || !pub || !data) {
        return DPS_ERR_NULL;
    }
    *data = NULL;
    for (list = node->localPubs; list != pub; list = list->next) {
        prev = list;
    }
    if (!list) {
        return DPS_ERR_MISSING;
    }
    if (prev) {
        prev->next = pub->next;
    } else {
        node->localPubs = pub->next;
    }
    *data = pub->data;
    FreePublication(pub);
    return DPS_ERR_OK;
}

DPS_Status DPS_Join(DPS_Node* node, DPS_NodeAddress* addr)
{
    DPS_Status ret = DPS_OK;
    PubList* pub;

    if (!addr || !node) {
        return DPS_ERR_NULL;
    }
    ret = AddRemotePublisher(node, addr, &pub);
    if (ret != DPS_OK) {
        if (ret == DPS_ERR_EXISTS) {
            DPS_ERRPRINT("Publisher %s already joined\n", DPS_NodeAddressText(addr));
            ret = DPS_OK;
        }
    } else {
        ret = SendSubscription(node, pub);
        if (ret != DPS_OK) {
            DeleteRemotePublisher(node, pub);
        }
    }
    return ret;
}

DPS_Status DPS_Leave(DPS_Node* node, DPS_NodeAddress* addr)
{
    PubList* pub = LookupRemotePublisher(node, addr);
    if (pub) {
        DeleteRemotePublisher(node, pub);
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
        int noChange;

        DPS_DBGPRINT("Subscribing to %d topics\n", numTopics);
        DumpTopics(sub->topics, sub->numTopics);

        DPS_BitVectorFuzzyHash(sub->needs, sub->bf);
        sub->next = node->localSubs;
        node->localSubs = sub;
        *subscription = sub;
        /*
         * Need to recompute the subscription union and see if anything changed
         */
        ret = RefreshSubscriptionInterests(node, NULL, NULL, NULL, NULL, &noChange);
        if (ret == DPS_OK && !noChange) {
            ret = FloodSubscriptions(node);
        }
    }
    return ret;
}

DPS_Status DPS_SubscribeCancel(DPS_Node* node, DPS_Subscription* subscription)
{
    DPS_Status ret;
    DPS_Subscription* sub;
    DPS_Subscription* prev = NULL;
    int noChange;

    if (!node || !subscription) {
        return DPS_ERR_NULL;
    }
    sub = node->localSubs;
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
        node->localSubs = sub->next;
    }
    DPS_DBGPRINT("Unsubscribing from %d topics\n", sub->numTopics);
    DumpTopics(sub->topics, sub->numTopics);
    FreeSubscription(sub);
    ret = RefreshSubscriptionInterests(node, NULL, NULL, NULL, NULL, &noChange);
    if (ret == DPS_OK && !noChange) {
        ret = FloodSubscriptions(node);
    }
    return ret;
}

DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service, DPS_NodeAddress* addr)
{
    DPS_Status dpsRet;
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
            memcpy(addr->addr, &ip6->sin6_addr, 16);
            addr->port = ntohs(ip6->sin6_port);
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
    for (sub = node->localSubs; sub != NULL; sub = sub->next) {
        DumpTopics(sub->topics, sub->numTopics);
    }
}
