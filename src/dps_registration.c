#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps/dps.h>
#include <dps/cbor.h>
#include <dps/dps_dbg.h>
#include <dps/dps_event.h>
#include <dps/dps_synchronous.h>
#include <dps/dps_registration.h>
#include <dps/network.h>
#include <dps/dps_internal.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define REGISTRATION_TTL   (60 * 60 * 8)  /* TTL is is seconds */
#define REG_PUT_TIMEOUT    (1000 * 5)     /* Timeout is in milliseconds */
#define REG_GET_TIMEOUT    (5000)          /* Timeout is in milliseconds */


const char* DPS_RegistryTopicString = "dps/registration_service";

typedef struct {
    char* tenant;
    DPS_Node* node;
    void* data;
    DPS_Publication* pub;
    DPS_Buffer payload;
    DPS_OnRegPutComplete cb;
    uv_timer_t timer;
} RegPut;

static DPS_Status EnumerateAddresses(DPS_CandidateList* list, uint16_t port)
{
    DPS_Status ret = DPS_OK;
    uv_interface_address_t* ifsAddrs;
    int numIfs;
    int r;

    port = htons(port);
    list->candidates = NULL;
    list->count = 0;
    r = uv_interface_addresses(&ifsAddrs, &numIfs);
    if (r) {
        ret = DPS_ERR_NETWORK;
    } else {
        DPS_Candidate* addrs = calloc(1, sizeof(DPS_Candidate) * numIfs);
        if (addrs) {
            int i;
            list->count = 0;
            for (i = 0; i < numIfs; ++i) {
                uv_interface_address_t* ifn = &ifsAddrs[i];
                if (!ifn->is_internal) {
                    ifn->address.address4.sin_port = port;
                    memcpy(&addrs[list->count++].addr.inaddr, &ifn->address, sizeof(ifn->address));
                }
            }
            list->candidates =  addrs;
        } else {
            ret = DPS_ERR_RESOURCES;
        }
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return ret;
}

static void RegPutCB(RegPut* reg, DPS_Status status)
{
    if (reg->pub) {
        DPS_DestroyPublication(reg->pub, NULL);
    }
    DPS_StopNode(reg->node);
    DPS_DestroyNode(reg->node);
    free(reg->tenant);
    free(reg->payload.base);
    reg->cb(status, reg->data);
    free(reg);
}

static void OnPutTimerClosedTO(uv_handle_t* handle)
{
    RegPutCB((RegPut*)handle->data, DPS_ERR_TIMEOUT);
}

static void OnPutTimeout(uv_timer_t* timer)
{
    uv_close((uv_handle_t*)timer, OnPutTimerClosedTO);
}

static void OnPutTimerClosedOK(uv_handle_t* handle)
{
    RegPutCB((RegPut*)handle->data, DPS_OK);
}

static void OnPutAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    RegPut* reg = (RegPut*)DPS_GetPublicationData(pub);
    uv_timer_stop(&reg->timer);
    uv_close((uv_handle_t*)&reg->timer, OnPutTimerClosedOK);
}

static DPS_Status EncodeAddr(DPS_Buffer* buf, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    uint16_t port;
    char addrText[INET6_ADDRSTRLEN];
    if (addr->inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)&addr->inaddr;
        uv_ip6_name(in6, addrText, sizeof(addrText));
        port = in6->sin6_port;
    } else {
        struct sockaddr_in* in4 = (struct sockaddr_in*)&addr->inaddr;
        uv_ip4_name(in4, addrText, sizeof(addrText));
        port = in4->sin_port;
    }
    port = ntohs(port);
    DPS_DBGPRINT("EncodeAddr %s/%d\n", addrText, port);
    ret = CBOR_EncodeUint8(buf, addr->inaddr.ss_family);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint16(buf, port);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeString(buf, addrText);
    }
    return ret;
}

static void OnLinkedPut(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegPut* reg = (RegPut*)data;

    if (ret == DPS_OK) {
        reg->pub = DPS_CreatePublication(node);
        if (!reg->pub) {
            ret = DPS_ERR_RESOURCES;
        } else {
            const char* topics[2];
            topics[0] = DPS_RegistryTopicString;
            topics[1] = reg->tenant;

            DPS_SetPublicationData(reg->pub, reg);
            DPS_InitPublication(reg->pub, topics, 2, DPS_TRUE, OnPutAck);
            ret = DPS_Publish(reg->pub, reg->payload.base, DPS_BufferUsed(&reg->payload), REGISTRATION_TTL, NULL);
            /*
             * Start a timer 
             */
            if (ret == DPS_OK) {
                int r;
                r = uv_timer_init(DPS_GetLoop(node), &reg->timer);
                if (!r) {
                    reg->timer.data = reg;
                    r = uv_timer_start(&reg->timer, OnPutTimeout, REG_PUT_TIMEOUT, 0);
                }
                if (r) {
                    ret = DPS_ERR_FAILURE;
                }
            }
        }
    }
    if (ret != DPS_OK) {
        RegPutCB(reg, ret);
    }
}

static void OnResolvePut(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret;
    RegPut* reg = (RegPut*)data;
    if (addr) {
        ret = DPS_Link(node, addr, OnLinkedPut, reg);
    } else {
        ret = DPS_ERR_UNRESOLVED;
    }
    if (ret != DPS_OK) {
        RegPutCB(reg, ret);
    }
}

static DPS_Status SetPutPayload(DPS_Buffer* payload, uint16_t port)
{
    DPS_Status ret;
    DPS_CandidateList addrList;
    size_t i;

    ret = EnumerateAddresses(&addrList, port);
    if (ret != DPS_OK) {
        return ret;
    }
    if (addrList.count == 0) {
        DPS_ERRPRINT("No addresses to register\n");
        ret = DPS_ERR_NO_ROUTE;
        goto Exit;
    }
    ret = DPS_BufferInit(payload, NULL, 8 + addrList.count * (INET6_ADDRSTRLEN + 10));
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * TODO - for privacy address list should be encrypted using a pre-shared tenant key.
     */
    DPS_DBGPRINT("Encoding %zu addresses\n", addrList.count);
    CBOR_EncodeUint8(payload, (uint8_t)addrList.count);
    for (i = 0; i < addrList.count; ++i) {
        ret = EncodeAddr(payload, &addrList.candidates[i].addr);
        if (ret != DPS_OK) {
            break;
        }
    }

Exit:
    free(addrList.candidates);
    return ret;
}

DPS_Status DPS_Registration_Put(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_OnRegPutComplete cb, void* data)
{
    DPS_Status ret;
    RegPut* reg;
    uint16_t localPort;

    localPort = DPS_GetPortNumber(node);
    if (!localPort) {
        return DPS_ERR_INVALID;
    }
    reg = calloc(1, sizeof(RegPut));
    if (!reg) {
        return DPS_ERR_RESOURCES;
    }
    reg->cb = cb;
    reg->data = data;
    reg->tenant = strdup(tenantString);
    reg->node = DPS_CreateNode("/");
    if (!reg->node || !reg->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }

    ret = DPS_StartNode(reg->node, DPS_MCAST_PUB_DISABLED, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        ret = SetPutPayload(&reg->payload, localPort);
        if (ret == DPS_OK) {
            char portStr[8];
            sprintf(portStr, "%d", port);
            ret = DPS_ResolveAddress(reg->node, host, portStr, OnResolvePut, reg);
        }
        if (ret != DPS_OK) {
            DPS_StopNode(reg->node);
        }
    }

Exit:
    if (ret != DPS_OK) {
        if (reg->node) {
            DPS_DestroyNode(reg->node);
        }
        if (reg->payload.base) {
            free(reg->payload.base);
        }
        if (reg->tenant) {
            free(reg->tenant);
        }
        free(reg);
    }
    return ret;
}

static void OnPutComplete(DPS_Status status, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, status);
}

DPS_Status DPS_Registration_PutSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString)
{
    DPS_Status ret;
    DPS_Event* event = DPS_CreateEvent();
    if (!event) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_Registration_Put(node, host, port, tenantString, OnPutComplete, event);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
    return ret;
}

typedef struct {
    char* tenant;
    DPS_Node* node;
    DPS_Subscription* sub;
    uint8_t max;
    void* data;
    DPS_OnRegGetComplete cb;
    uv_timer_t timer;
    DPS_CandidateList localAddrs;
    DPS_CandidateList list;
} RegGet;

static DPS_Status DecodeAddr(DPS_Buffer* buf, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    char* addrText;
    size_t len;
    uint8_t family;
    uint16_t port;

    ret = CBOR_DecodeUint8(buf, &family);
    if (ret == DPS_OK) {
        ret = CBOR_DecodeUint16(buf, &port);
    }
    if (ret == DPS_OK) {
        ret = CBOR_DecodeString(buf, &addrText, &len);
    }
    if (ret == DPS_OK) {
        int r;
        DPS_DBGPRINT("DecodeAddr %s/%d\n", addrText, port);
        if (family == AF_INET6) {
            r = uv_ip6_addr(addrText, port, (struct sockaddr_in6*)&addr->inaddr);
        } else {
            r = uv_ip4_addr(addrText, port, (struct sockaddr_in*)&addr->inaddr);
        }
        if (r) {
            ret = DPS_ERR_INVALID;
        }
    }
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DecodeAddr failed: %s\n", DPS_ErrTxt(ret));
    }
    return ret;
}

static void RegGetCB(RegGet* reg, DPS_Status status)
{
    if (reg->sub) {
        DPS_DestroySubscription(reg->sub);
    }
    DPS_StopNode(reg->node);
    DPS_DestroyNode(reg->node);
    free(reg->tenant);
    reg->cb(&reg->list, status, reg->data);
    free(reg->localAddrs.candidates);
    free(reg);
}

static void OnGetTimerClosed(uv_handle_t* handle)
{
    RegGet* reg = (RegGet*)handle->data;
    RegGetCB(reg, DPS_OK);
}

static void OnGetTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();
    uv_close((uv_handle_t*)timer, OnGetTimerClosed);
}

static int IsAddrListed(DPS_CandidateList* list, DPS_NodeAddress* addr)
{
    size_t i;

    for (i = 0; i < list->count; ++i) {
        if (DPS_SameAddr(&list->candidates[i].addr, (struct sockaddr*)&addr->inaddr)) {
            return DPS_TRUE;
        }
    }
    return DPS_FALSE;
}

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    RegGet* reg = (RegGet*)DPS_GetSubscriptionData(sub);

    DPS_DBGPRINT("OnPub reg=%p\n", reg);
    if (reg) {
        DPS_Status ret;
        uint8_t count;
        DPS_Buffer buf;
        /*
         * Parse out the addresses from the payload
         */
        DPS_BufferInit(&buf, data, len);
        ret = CBOR_DecodeUint8(&buf, &count);
        if (ret == DPS_OK) {
            while (count--) {
                /*
                 * Stop if we have reached the max candidates 
                 */
                if (reg->list.count == reg->max) {
                    DPS_DestroySubscription(reg->sub);
                    reg->sub = NULL;
                    uv_timer_stop(&reg->timer);
                    uv_close((uv_handle_t*)&reg->timer, OnGetTimerClosed);
                    break;
                }
                ret = DecodeAddr(&buf, &reg->list.candidates[reg->list.count].addr);
                if (ret != DPS_OK) {
                    break;
                }
                /*
                 * Check this isn't our own address
                 */
                if (!IsAddrListed(&reg->localAddrs, &reg->list.candidates[reg->list.count].addr)) {
                    ++reg->list.count;
                }
            }
        }
    }
}

static void OnLinkedGet(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegGet* reg = (RegGet*)data;

    DPS_DBGTRACE();
    if (ret == DPS_OK) {
        const char* topics[2];
        /*
         * Subscribe to our tenant topic string
         */
        topics[0] = DPS_RegistryTopicString;
        topics[1] = reg->tenant;
        reg->sub = DPS_CreateSubscription(node, topics, 2);
        if (!reg->sub) {
            ret = DPS_ERR_RESOURCES;
        } else {
            DPS_SetSubscriptionData(reg->sub, reg);
            ret = DPS_Subscribe(reg->sub, OnPub);
            /*
             * Start a timer 
             */
            if (ret == DPS_OK) {
                int r;
                r = uv_timer_init(DPS_GetLoop(node), &reg->timer);
                if (!r) {
                    reg->timer.data = reg;
                    r = uv_timer_start(&reg->timer, OnGetTimeout, REG_GET_TIMEOUT, 0);
                }
                if (r) {
                    ret = DPS_ERR_FAILURE;
                }
            }
        }
    }
    if (ret != DPS_OK) {
        RegGetCB(reg, ret);
    }
}

static void OnResolveGet(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret;
    RegGet* reg = (RegGet*)data;

    DPS_DBGTRACE();
    if (addr) {
        ret = DPS_Link(node, addr, OnLinkedGet, reg);
    } else {
        ret = DPS_ERR_UNRESOLVED;
    }
    if (ret != DPS_OK) {
        RegGetCB(reg, ret);
    }
}

DPS_Status DPS_Registration_Get(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_CandidateList* list, DPS_OnRegGetComplete cb, void* data)
{
    DPS_Status ret;
    RegGet* reg;
    uint16_t localPort;

    DPS_DBGTRACE();
    if (!list) {
        return DPS_ERR_NULL;
    }
    if (list->count < 1) {
        return DPS_ERR_INVALID;
    }
    localPort = DPS_GetPortNumber(node);
    if (!localPort) {
        return DPS_ERR_INVALID;
    }
    /*
     * Clear candidate list
     */
    memset(list->candidates, 0, list->count * sizeof(DPS_Candidate));
    reg = calloc(1, sizeof(RegGet));
    if (!reg) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * We need to know the local addresses so we can filter them out in the responses
     */
    ret = EnumerateAddresses(&reg->localAddrs, localPort);
    if (ret != DPS_OK) {
        goto Exit;
    }
    reg->cb = cb;
    reg->data = data;
    reg->max = list->count;
    reg->tenant = strdup(tenantString);
    if (!reg->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    reg->list.candidates = list->candidates;
    reg->list.count = 0;

    reg->node = DPS_CreateNode("/");
    if (!reg->node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_StartNode(reg->node, DPS_MCAST_PUB_DISABLED, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        char portStr[8];
        sprintf(portStr, "%d", port);
        ret = DPS_ResolveAddress(reg->node, host, portStr, OnResolveGet, reg);
        if (ret != DPS_OK) {
            DPS_StopNode(reg->node);
        }
    }

Exit:
    if (ret != DPS_OK) {
        if (reg->node) {
            DPS_DestroyNode(reg->node);
        }
        if (reg->tenant) {
            free(reg->tenant);
        }
        free(reg);
    }
    return ret;
}

typedef struct {
    DPS_CandidateList* list;
    DPS_Event* event;
} GetResult;

static void OnGetComplete(DPS_CandidateList* candidates, DPS_Status status, void* data)
{
    GetResult* getResult = (GetResult*)data;
    getResult->list->count = candidates->count;
    DPS_SignalEvent(getResult->event, status);
}

DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_CandidateList* list)
{
    DPS_Status ret;
    GetResult getResult;

    getResult.event = DPS_CreateEvent();
    getResult.list = list;
    if (!getResult.event) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_Registration_Get(node, host, port, tenantString, list, OnGetComplete, &getResult);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(getResult.event);
    }
    DPS_DestroyEvent(getResult.event);
    return ret;
}

typedef struct {
    void* data;
    DPS_OnRegLinkToComplete cb;
    DPS_CandidateList list;
    DPS_Candidate* candidate;
} LinkTo;

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    LinkTo* linkTo = (LinkTo*)data;

    if (status == DPS_OK) {
        linkTo->candidate->flags = DPS_CANDIDATE_LINKED;
    } else {
        /*
         * Keep trying other candidates
         */
        linkTo->candidate->flags = DPS_CANDIDATE_FAILED;
        if (DPS_Registration_LinkTo(node, &linkTo->list, linkTo->cb, linkTo->data) == DPS_OK) {
            free(linkTo);
            return;
        }
    }
    linkTo->cb(node, &linkTo->list, addr, status, linkTo->data);
    free(linkTo);
}

DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_CandidateList* list, DPS_OnRegLinkToComplete cb, void* data)
{
    size_t i;
    size_t untried = 0;
    /*
     * Check there is at leas on candidate that hasn't been tried yet
     */
    for (i = 0; i < list->count; ++i) {
        if (list->candidates[untried].flags == 0) {
            ++untried;
        }
    }
    while (untried) {
        uint32_t r = DPS_Rand() % list->count;
        if (list->candidates[r].flags == 0) {
            DPS_Status ret;
            LinkTo* linkTo = malloc(sizeof(LinkTo));

            linkTo->cb = cb;
            linkTo->data = data;
            linkTo->list = *list;
            linkTo->candidate = &list->candidates[r];

            list->candidates[r].flags = DPS_CANDIDATE_TRYING;
            ret = DPS_Link(node, &list->candidates[r].addr, OnLinked, linkTo);
            if (ret == DPS_OK) {
                break;
            }
            list->candidates[r].flags = DPS_CANDIDATE_FAILED;
            free(linkTo);
            --untried;
        }
    }
    if (untried) {
        return DPS_ERR_OK;
    } else {
        return DPS_ERR_NO_ROUTE;
    }
}

typedef struct {
    DPS_Event* event;
    DPS_NodeAddress* addr;
} LinkResult;

static void OnRegLinkTo(DPS_Node* node, DPS_CandidateList* list, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    LinkResult* linkResult = (LinkResult*)data;
    if (status == DPS_OK) {
        *linkResult->addr = *addr;
    }
    DPS_SignalEvent(linkResult->event, status);
}

DPS_Status DPS_Registration_LinkToSyn(DPS_Node* node, DPS_CandidateList* candidates, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    LinkResult linkResult;

    linkResult.event = DPS_CreateEvent();
    if (!linkResult.event) {
        return DPS_ERR_RESOURCES;
    }
    linkResult.addr = addr;

    ret = DPS_Registration_LinkTo(node, candidates, OnRegLinkTo, &linkResult);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(linkResult.event);
    }
    DPS_DestroyEvent(linkResult.event);
    return ret;
}
