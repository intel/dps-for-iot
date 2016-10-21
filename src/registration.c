#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include <dps/registration.h>
#include "cbor.h"
#include "internal.h"
#include "network.h"

#ifdef _WIN32
#define strdup(s) _strdup(s)
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define REGISTRATION_TTL   (60 * 60 * 8)  /* TTL is is seconds */
#define REG_PUT_TIMEOUT    (1000)         /* Timeout is in milliseconds */
#define REG_GET_TIMEOUT    (1000)         /* Timeout is in milliseconds */

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_DBGTRACE();
}

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

static void RegPutCB(RegPut* regPut, DPS_Status status)
{
    DPS_DBGTRACE();
    if (regPut->pub) {
        DPS_DestroyPublication(regPut->pub, NULL);
    }
    DPS_DestroyNode(regPut->node, OnNodeDestroyed, NULL);
    free(regPut->tenant);
    free(regPut->payload.base);
    regPut->cb(status, regPut->data);
    free(regPut);
}

static void OnPutTimerClosedTO(uv_handle_t* handle)
{
    DPS_DBGTRACE();
    RegPutCB((RegPut*)handle->data, DPS_ERR_TIMEOUT);
}

static void OnPutTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();
    uv_close((uv_handle_t*)timer, OnPutTimerClosedTO);
}

static void OnPutTimerClosedOK(uv_handle_t* handle)
{
    DPS_DBGTRACE();
    RegPutCB((RegPut*)handle->data, DPS_OK);
}

static void OnPutAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_DBGTRACE();
    RegPut* regPut = (RegPut*)DPS_GetPublicationData(pub);
    uv_timer_stop(&regPut->timer);
    uv_close((uv_handle_t*)&regPut->timer, OnPutTimerClosedOK);
}

static DPS_Status EncodeAddr(DPS_Buffer* buf, struct sockaddr* addr, uint16_t port)
{
    DPS_Status ret;
    char txt[INET6_ADDRSTRLEN];

    if (addr->sa_family == AF_INET6) {
        uv_ip6_name((const struct sockaddr_in6*)addr, txt, sizeof(txt));
    } else {
        uv_ip4_name((const struct sockaddr_in*)addr, txt, sizeof(txt));
    }
    DPS_DBGPRINT("EncodeAddr %s/%d\n", txt, port);
    ret = CBOR_EncodeUint16(buf, port);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeString(buf, txt);
    }
    return ret;
}

static void OnLinkedPut(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegPut* regPut = (RegPut*)data;

    if (ret == DPS_OK) {
        regPut->pub = DPS_CreatePublication(node);
        if (!regPut->pub) {
            ret = DPS_ERR_RESOURCES;
        } else {
            const char* topics[2];
            topics[0] = DPS_RegistryTopicString;
            topics[1] = regPut->tenant;

            DPS_SetPublicationData(regPut->pub, regPut);
            DPS_InitPublication(regPut->pub, topics, 2, DPS_TRUE, OnPutAck);
            ret = DPS_Publish(regPut->pub, regPut->payload.base, DPS_BufferUsed(&regPut->payload), REGISTRATION_TTL, NULL);
            /*
             * Start a timer 
             */
            if (ret == DPS_OK) {
                int r;
                r = uv_timer_init(DPS_GetLoop(node), &regPut->timer);
                if (!r) {
                    regPut->timer.data = regPut;
                    r = uv_timer_start(&regPut->timer, OnPutTimeout, REG_PUT_TIMEOUT, 0);
                }
                if (r) {
                    ret = DPS_ERR_FAILURE;
                }
            }
        }
    }
    if (ret != DPS_OK) {
        RegPutCB(regPut, ret);
    }
}

static void OnResolvePut(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret;
    RegPut* regPut = (RegPut*)data;
    if (addr) {
        ret = DPS_Link(node, addr, OnLinkedPut, regPut);
    } else {
        ret = DPS_ERR_UNRESOLVED;
    }
    if (ret != DPS_OK) {
        RegPutCB(regPut, ret);
    }
}

static DPS_Status BuildPutPayload(DPS_Buffer* payload, uint16_t port)
{
    DPS_Status ret;
    uv_interface_address_t* ifsAddrs;
    int numIfs;
    int extIfs = 0;
    int r;
    size_t i;

    r = uv_interface_addresses(&ifsAddrs, &numIfs);
    if (r) {
        return DPS_ERR_NETWORK;
    }
    /*
     * Only interested in external interfaces
     */
    for (i = 0; i < numIfs; ++i) {
        uv_interface_address_t* ifn = &ifsAddrs[i];
        if (!ifn->is_internal) {
            ++extIfs;
        }
    }
    ret = DPS_BufferInit(payload, NULL, 8 + extIfs * (INET6_ADDRSTRLEN + 10));
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * TODO - for privacy address list should be encrypted using a pre-shared tenant key.
     */
    DPS_DBGPRINT("Encoding %d addresses\n", extIfs);
    CBOR_EncodeUint8(payload, (uint8_t)extIfs);
    for (i = 0; i < numIfs; ++i) {
        uv_interface_address_t* ifn = &ifsAddrs[i];
        if (!ifn->is_internal) {
            ret = EncodeAddr(payload, (struct sockaddr*)&ifn->address, port);
            if (ret != DPS_OK) {
                break;
            }
        }
    }

Exit:
    uv_free_interface_addresses(ifsAddrs, numIfs);
    return ret;
}

DPS_Status DPS_Registration_Put(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_OnRegPutComplete cb, void* data)
{
    DPS_Status ret;
    RegPut* regPut;
    uint16_t localPort;

    localPort = DPS_GetPortNumber(node);
    if (!localPort) {
        return DPS_ERR_INVALID;
    }
    regPut = calloc(1, sizeof(RegPut));
    if (!regPut) {
        return DPS_ERR_RESOURCES;
    }
    regPut->cb = cb;
    regPut->data = data;
    regPut->tenant = strdup(tenantString);
    regPut->node = DPS_CreateNode("/");
    if (!regPut->node || !regPut->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }

    ret = DPS_StartNode(regPut->node, DPS_MCAST_PUB_DISABLED, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        ret = BuildPutPayload(&regPut->payload, localPort);
        if (ret == DPS_OK) {
            char portStr[8];
            sprintf(portStr, "%d", port);
            ret = DPS_ResolveAddress(regPut->node, host, portStr, OnResolvePut, regPut);
        }
    }

Exit:
    if (ret != DPS_OK) {
        if (regPut->node) {
            DPS_DestroyNode(regPut->node, OnNodeDestroyed, NULL);
        }
        if (regPut->payload.base) {
            free(regPut->payload.base);
        }
        if (regPut->tenant) {
            free(regPut->tenant);
        }
        free(regPut);
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
    uint16_t port;
    void* data;
    DPS_OnRegGetComplete cb;
    uv_timer_t timer;
    DPS_RegistrationList* regs;
} RegGet;

static void RegGetCB(RegGet* regGet, DPS_Status status)
{
    DPS_DBGTRACE();
    if (regGet->sub) {
        DPS_DestroySubscription(regGet->sub);
    }
    DPS_DestroyNode(regGet->node, OnNodeDestroyed, NULL);
    free(regGet->tenant);
    regGet->cb(regGet->regs, status, regGet->data);
    free(regGet);
}

static void OnGetTimerClosed(uv_handle_t* handle)
{
    RegGet* regGet = (RegGet*)handle->data;
    RegGetCB(regGet, DPS_OK);
}

static void OnGetTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();
    uv_close((uv_handle_t*)timer, OnGetTimerClosed);
}

#define AddrGetPort(a)     (((struct sockaddr_in*)(a))->sin_port)
#define AddrSetPort(a, p)  (((struct sockaddr_in*)(a))->sin_port = (p))

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    RegGet* regGet = (RegGet*)DPS_GetSubscriptionData(sub);

    DPS_DBGPRINT("OnPub regGet=%p\n", regGet);
    if (regGet) {
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
                uint16_t port;
                char* host;
                size_t len;
                /*
                 * Stop if we have reached the max registrations 
                 */
                if (regGet->regs->count == regGet->regs->size) {
                    DPS_DestroySubscription(regGet->sub);
                    regGet->sub = NULL;
                    uv_timer_stop(&regGet->timer);
                    uv_close((uv_handle_t*)&regGet->timer, OnGetTimerClosed);
                    break;
                }
                if (CBOR_DecodeUint16(&buf, &port) != DPS_OK) {
                    break;
                }
                if (CBOR_DecodeString(&buf, &host, &len) != DPS_OK) {
                    break;
                }
                regGet->regs->list[regGet->regs->count].port = port;
                regGet->regs->list[regGet->regs->count].host = strdup(host);
                ++regGet->regs->count;
            }
        }
    }
}

static void OnLinkedGet(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegGet* regGet = (RegGet*)data;

    DPS_DBGTRACE();
    if (ret == DPS_OK) {
        const char* topics[2];
        /*
         * Subscribe to our tenant topic string
         */
        topics[0] = DPS_RegistryTopicString;
        topics[1] = regGet->tenant;
        regGet->sub = DPS_CreateSubscription(node, topics, 2);
        if (!regGet->sub) {
            ret = DPS_ERR_RESOURCES;
        } else {
            DPS_SetSubscriptionData(regGet->sub, regGet);
            ret = DPS_Subscribe(regGet->sub, OnPub);
            /*
             * Start a timer 
             */
            if (ret == DPS_OK) {
                int r;
                r = uv_timer_init(DPS_GetLoop(node), &regGet->timer);
                if (!r) {
                    regGet->timer.data = regGet;
                    r = uv_timer_start(&regGet->timer, OnGetTimeout, REG_GET_TIMEOUT, 0);
                }
                if (r) {
                    ret = DPS_ERR_FAILURE;
                }
            }
        }
    }
    if (ret != DPS_OK) {
        RegGetCB(regGet, ret);
    }
}

static void OnResolveGet(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret;
    RegGet* regGet = (RegGet*)data;

    DPS_DBGTRACE();
    if (addr) {
        ret = DPS_Link(node, addr, OnLinkedGet, regGet);
    } else {
        ret = DPS_ERR_UNRESOLVED;
    }
    if (ret != DPS_OK) {
        RegGetCB(regGet, ret);
    }
}

DPS_Status DPS_Registration_Get(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_RegistrationList* regs, DPS_OnRegGetComplete cb, void* data)
{
    DPS_Status ret;
    RegGet* regGet;
    uint16_t localPort;

    DPS_DBGTRACE();
    if (!regs) {
        return DPS_ERR_NULL;
    }
    if (regs->size < 1) {
        return DPS_ERR_INVALID;
    }
    localPort = DPS_GetPortNumber(node);
    if (!localPort) {
        return DPS_ERR_INVALID;
    }
    /*
     * Clear candidate list
     */
    regGet = calloc(1, sizeof(RegGet));
    if (!regGet) {
        return DPS_ERR_RESOURCES;
    }
    regGet->port = localPort;
    regGet->cb = cb;
    regGet->data = data;
    regGet->regs = regs;
    regGet->regs->count = 0;
    regGet->tenant = strdup(tenantString);
    if (!regGet->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    regGet->node = DPS_CreateNode("/");
    if (!regGet->node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_StartNode(regGet->node, DPS_MCAST_PUB_DISABLED, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        char portStr[8];
        sprintf(portStr, "%d", port);
        ret = DPS_ResolveAddress(regGet->node, host, portStr, OnResolveGet, regGet);
    }

Exit:
    if (ret != DPS_OK) {
        if (regGet->node) {
            DPS_DestroyNode(regGet->node, OnNodeDestroyed, NULL);
        }
        if (regGet->tenant) {
            free(regGet->tenant);
        }
        free(regGet);
    }
    return ret;
}

typedef struct {
    DPS_RegistrationList* regs;
    DPS_Event* event;
} GetResult;

static void OnGetComplete(DPS_RegistrationList* regs, DPS_Status status, void* data)
{
    GetResult* getResult = (GetResult*)data;

    DPS_DBGTRACE();
    DPS_SignalEvent(getResult->event, status);
}

DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_RegistrationList* regs)
{
    DPS_Status ret;
    GetResult getResult;

    DPS_DBGTRACE();
    getResult.event = DPS_CreateEvent();
    getResult.regs = regs;
    regs->count = 0;
    if (!getResult.event) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_Registration_Get(node, host, port, tenantString, regs, OnGetComplete, &getResult);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(getResult.event);
    }
    DPS_DestroyEvent(getResult.event);
    return ret;
}

typedef struct {
    void* data;
    DPS_OnRegLinkToComplete cb;
    DPS_RegistrationList* regs;
    DPS_Registration* candidate;
} LinkTo;

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    LinkTo* linkTo = (LinkTo*)data;

    DPS_DBGTRACE();
    if (status == DPS_OK) {
        assert(addr);
        linkTo->candidate->flags = DPS_CANDIDATE_LINKED;
    } else {
        /*
         * Keep trying other registrations
         */
        linkTo->candidate->flags = DPS_CANDIDATE_FAILED;
        if (DPS_Registration_LinkTo(node, linkTo->regs, linkTo->cb, linkTo->data) == DPS_OK) {
            free(linkTo);
            return;
        }
    }
    linkTo->cb(node, linkTo->regs, addr, status, linkTo->data);
    free(linkTo);
}

static int IsLocalAddr(DPS_NodeAddress* addr, uint16_t port)
{
    int local = DPS_FALSE;
    uv_interface_address_t* ifsAddrs;
    int numIfs;
    int r;

    port = htons(port);
    if (AddrGetPort(addr) != port) {
        return DPS_FALSE;
    }
    r = uv_interface_addresses(&ifsAddrs, &numIfs);
    if (!r) {
        size_t i;
        for (i = 0; i < numIfs; ++i) {
            uv_interface_address_t* ifn = &ifsAddrs[i];
            if (!ifn->is_internal) {
                DPS_NodeAddress a;
                memcpy(&a.inaddr, &ifn->address, sizeof(ifn->address));
                AddrSetPort(&a.inaddr, port);
                if (DPS_SameAddr(addr, &a)) {
                    local = DPS_TRUE;
                    break;
                }
            }
        }
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return local;
}

static void OnResolve(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret = DPS_ERR_NO_ROUTE;
    LinkTo* linkTo = (LinkTo*)data;

    DPS_DBGTRACE();
    if (addr) {
        if (IsLocalAddr(addr, DPS_GetPortNumber(node))) {
            linkTo->candidate->flags = DPS_CANDIDATE_INVALID;
        } else {
            ret = DPS_Link(node, addr, OnLinked, linkTo);
        }
    }
    if (ret != DPS_OK) {
        /*
         * Keep trying other registrations
         */
        linkTo->candidate->flags |= DPS_CANDIDATE_FAILED;
        if (DPS_Registration_LinkTo(node, linkTo->regs, linkTo->cb, linkTo->data) != DPS_OK) {
            linkTo->cb(node, linkTo->regs, addr, ret, linkTo->data);
        }
        free(linkTo);
    }
}

DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_RegistrationList* regs, DPS_OnRegLinkToComplete cb, void* data)
{
    DPS_Status ret = DPS_ERR_NO_ROUTE;
    size_t i;
    size_t untried = 0;
    /*
     * Check there is at least one candidate that hasn't been tried yet
     */
    for (i = 0; i < regs->count; ++i) {
        if (regs->list[untried].flags == 0) {
            ++untried;
        }
    }
    while (untried) {
        uint32_t r = DPS_Rand() % regs->count;
        if (regs->list[r].flags == 0) {
            char portTxt[8];
            LinkTo* linkTo = malloc(sizeof(LinkTo));

            linkTo->cb = cb;
            linkTo->data = data;
            linkTo->regs = regs;
            linkTo->candidate = &regs->list[r];

            regs->list[r].flags = DPS_CANDIDATE_TRYING;
            sprintf(portTxt, "%d", regs->list[r].port);
            ret = DPS_ResolveAddress(node, regs->list[r].host, portTxt, OnResolve, linkTo);
            if (ret == DPS_OK) {
                break;
            }
            DPS_ERRPRINT("DPS_ResolveAddress returned %s\n", DPS_ErrTxt(ret));
            regs->list[r].flags = DPS_CANDIDATE_FAILED;
            free(linkTo);
            --untried;
        }
    }
    return ret;
}

typedef struct {
    DPS_Event* event;
    DPS_NodeAddress* addr;
} LinkResult;

static void OnRegLinkTo(DPS_Node* node, DPS_RegistrationList* regs, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    LinkResult* linkResult = (LinkResult*)data;

    DPS_DBGTRACE();
    if (status == DPS_OK) {
        *linkResult->addr = *addr;
    }
    DPS_SignalEvent(linkResult->event, status);
}

DPS_Status DPS_Registration_LinkToSyn(DPS_Node* node, DPS_RegistrationList* regs, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    LinkResult linkResult;

    linkResult.event = DPS_CreateEvent();
    if (!linkResult.event) {
        return DPS_ERR_RESOURCES;
    }
    linkResult.addr = addr;

    ret = DPS_Registration_LinkTo(node, regs, OnRegLinkTo, &linkResult);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(linkResult.event);
    }
    DPS_DestroyEvent(linkResult.event);
    return ret;
}

DPS_RegistrationList* DPS_CreateRegistrationList(uint8_t size)
{
    DPS_RegistrationList* regs = calloc(1, sizeof(DPS_RegistrationList) + (size - 1) * sizeof(DPS_Registration));
    if (regs) {
        regs->size = size;
    }
    return regs;
}

void DPS_DestroyRegistrationList(DPS_RegistrationList* regs)
{
    if (regs) {
        while (regs->size--) {
            if (regs->list[regs->size].host) {
                free(regs->list[regs->size].host);
            }
        }
        free(regs);
    }
}
