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
#include <safe_lib.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include <dps/registration.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include "node.h"
#include "topics.h"
#include "compat.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define REGISTRATION_TTL   (60 * 60 * 8)  /* TTL is is seconds */

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_DBGTRACE();
}

const char* DPS_RegistryTopicString = "dps/registration_service";

#define AddrGetPort(a)     (((struct sockaddr_in*)(a))->sin_port)
#define AddrSetPort(a, p)  (((struct sockaddr_in*)(a))->sin_port = (p))

static int IsLocalAddr(const DPS_NodeAddress* addr, const DPS_NodeAddress* localAddr)
{
    int local = DPS_FALSE;
    uint16_t port;
    uv_interface_address_t* ifsAddrs = NULL;
    int numIfs = 0;
    int r;

    if (addr->type != localAddr->type) {
        goto Exit;
    }
    switch (addr->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        port = AddrGetPort(&localAddr->u.inaddr);
        if (AddrGetPort(&addr->u.inaddr) != port) {
            goto Exit;
        }
        r = uv_interface_addresses(&ifsAddrs, &numIfs);
        if (!r) {
            int i;
            for (i = 0; i < numIfs; ++i) {
                uv_interface_address_t* ifn = &ifsAddrs[i];
                if (!ifn->is_internal) {
                    DPS_NodeAddress a;
                    a.type = addr->type;
                    memcpy_s(&a.u.inaddr, sizeof(a.u.inaddr), &ifn->address, sizeof(ifn->address));
                    AddrSetPort(&a.u.inaddr, port);
                    if (DPS_SameAddr(addr, &a)) {
                        local = DPS_TRUE;
                        goto Exit;
                    }
                }
            }
        }
        break;
    case DPS_PIPE:
        local = !strcmp(addr->u.path, localAddr->u.path);
        break;
    default:
        break;
    }

Exit:
    if (ifsAddrs) {
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return local;
}

static int IsLocalAddrText(const char* addrText, const DPS_NodeAddress* localAddr)
{
    int local = DPS_FALSE;
    char host[DPS_MAX_HOST_LEN + 1];
    char service[DPS_MAX_SERVICE_LEN + 1];
    uint16_t localPort;
    uv_interface_address_t* ifsAddrs = NULL;
    int numIfs = 0;
    DPS_Status ret;
    int r;

    switch (localAddr->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        ret = DPS_SplitAddress(addrText, host, sizeof(host), service, sizeof(service));
        if (ret != DPS_OK) {
            goto Exit;
        }
        localPort = AddrGetPort(&localAddr->u.inaddr);
        r = uv_interface_addresses(&ifsAddrs, &numIfs);
        if (!r) {
            int i;
            for (i = 0; i < numIfs; ++i) {
                uv_interface_address_t* ifn = &ifsAddrs[i];
                if (!ifn->is_internal) {
                    struct sockaddr_storage ss;
                    memcpy_s(&ss, sizeof(ss), &ifn->address, sizeof(ifn->address));
                    AddrSetPort(&ss, localPort);
                    if (!strcmp(addrText, DPS_NetAddrText((const struct sockaddr*)&ss))) {
                        local = DPS_TRUE;
                        goto Exit;
                    }
                }
            }
        }
        break;
    case DPS_PIPE:
        local = !strcmp(addrText, localAddr->u.path);
        break;
    default:
        break;
    }

Exit:
    if (ifsAddrs) {
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return local;
}

typedef struct {
    char* tenant;
    DPS_Node* node;
    void* data;
    DPS_Publication* pub;
    DPS_TxBuffer payload;
    DPS_OnRegPutComplete cb;
    uv_timer_t timer;
    DPS_NodeAddress addr;
    int linked;
    DPS_Status status;
    uint16_t timeout;
} RegPut;

static void RegPutCB(RegPut* regPut)
{
    DPS_DBGTRACE();
    if (regPut->pub) {
        DPS_DestroyPublication(regPut->pub);
    }
    DPS_DestroyNode(regPut->node, OnNodeDestroyed, NULL);
    free(regPut->tenant);
    free(regPut->payload.base);
    regPut->cb(regPut->status, regPut->data);
    free(regPut);
}

static void OnPutUnlinkCB(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
    DPS_DBGTRACE();
    RegPutCB((RegPut*)data);
}

static void PutUnlink(RegPut* regPut)
{
    DPS_Status ret = DPS_OK;
    if (regPut->linked) {
        ret = DPS_Unlink(regPut->node, &regPut->addr, OnPutUnlinkCB, regPut);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("DPS_Unlink failed - %s\n", DPS_ErrTxt(ret));
        }
    }
    if (!regPut->linked || ret != DPS_OK) {
        RegPutCB(regPut);
    }
}

static void OnPutTimerClosedTO(uv_handle_t* handle)
{
    RegPut* regPut = (RegPut*)handle->data;
    DPS_DBGTRACE();
    regPut->status = DPS_ERR_TIMEOUT;
    PutUnlink(regPut);
}

static void OnPutTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();
    uv_close((uv_handle_t*)timer, OnPutTimerClosedTO);
}

static void OnPutTimerClosedOK(uv_handle_t* handle)
{
    RegPut* regPut = (RegPut*)handle->data;
    DPS_DBGTRACE();
    regPut->status = DPS_OK;
    PutUnlink(regPut);
}

static void OnPutAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_DBGTRACE();
    RegPut* regPut = (RegPut*)DPS_GetPublicationData(pub);
    uv_timer_stop(&regPut->timer);
    uv_close((uv_handle_t*)&regPut->timer, OnPutTimerClosedOK);
}

static void OnLinkedPut(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegPut* regPut = (RegPut*)data;

    regPut->status = ret;
    if (regPut->status == DPS_OK) {
        DPS_CopyAddress(&regPut->addr, addr);
        regPut->linked = DPS_TRUE;
        regPut->pub = DPS_CreatePublication(node);
        if (!regPut->pub) {
            regPut->status = DPS_ERR_RESOURCES;
            goto Exit;
        }
        const char* topics[2];
        topics[0] = DPS_RegistryTopicString;
        topics[1] = regPut->tenant;

        DPS_SetPublicationData(regPut->pub, regPut);
        regPut->status = DPS_InitPublication(regPut->pub, topics, 2, DPS_TRUE, NULL, OnPutAck);
        if (regPut->status != DPS_OK) {
            goto Exit;
        }
        regPut->status = DPS_Publish(regPut->pub, regPut->payload.base,
                                     DPS_TxBufferUsed(&regPut->payload), REGISTRATION_TTL);
        if (regPut->status != DPS_OK) {
            goto Exit;
        }
        /*
         * Start a timer
         */
        int r;
        r = uv_timer_init(node->loop, &regPut->timer);
        if (!r) {
            regPut->timer.data = regPut;
            r = uv_timer_start(&regPut->timer, OnPutTimeout, regPut->timeout, 0);
        }
        if (r) {
            regPut->status = DPS_ERR_FAILURE;
            goto Exit;
        }
    }
Exit:
    if (regPut->status != DPS_OK) {
        PutUnlink(regPut);
    }
}

static DPS_Status BuildPutPayload(DPS_TxBuffer* payload, const DPS_NodeAddress* addr)
{
    DPS_Status ret;
    uv_interface_address_t* ifsAddrs = NULL;
    int numIfs = 0;
    uint8_t extIfs = 0;
    uint16_t port;
    int r;
    int i;

    switch (addr->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        r = uv_interface_addresses(&ifsAddrs, &numIfs);
        if (r) {
            ret = DPS_ERR_NETWORK;
            goto Exit;
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
        ret = DPS_TxBufferInit(payload, NULL, CBOR_SIZEOF_UINT(extIfs) +
                               extIfs * DPS_NODE_ADDRESS_MAX_STRING_LEN);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /*
         * TODO - for privacy address list should be encrypted using a pre-shared tenant key.
         */
        DPS_DBGPRINT("Encoding %d addresses\n", extIfs);
        ret = CBOR_EncodeUint8(payload, (uint8_t)extIfs);
        assert(ret == DPS_OK);
        port = AddrGetPort(&addr->u.inaddr);
        for (i = 0; i < numIfs; ++i) {
            uv_interface_address_t* ifn = &ifsAddrs[i];
            struct sockaddr* sa = (struct sockaddr*)&ifn->address;
            if (ifn->is_internal ||
                ((sa->sa_family == AF_INET6) &&
                 IN6_IS_ADDR_LINKLOCAL(&((const struct sockaddr_in6*)sa)->sin6_addr))) {
                continue;
            }
            AddrSetPort(sa, port);
            ret = CBOR_EncodeString(payload, DPS_NetAddrText(sa));
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
        break;
    case DPS_PIPE:
        ret = DPS_TxBufferInit(payload, NULL, CBOR_SIZEOF_UINT(1) + DPS_NODE_ADDRESS_MAX_STRING_LEN);
        if (ret != DPS_OK) {
            goto Exit;
        }
        DPS_DBGPRINT("Encoding 1 addresses\n");
        ret = CBOR_EncodeUint8(payload, 1);
        assert(ret == DPS_OK);
        ret = CBOR_EncodeString(payload, DPS_NodeAddrToString(addr));
        break;
    default:
        ret = DPS_ERR_INVALID;
        break;
    }

Exit:
    if (ifsAddrs) {
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return ret;
}

DPS_Status DPS_Registration_Put(DPS_Node* node, const char* addrText, const char* tenantString,
                                uint16_t timeout, DPS_OnRegPutComplete cb, void* data)
{
    DPS_Status ret;
    RegPut* regPut;
    const DPS_NodeAddress* localAddr;

    DPS_DBGTRACE();

    localAddr = DPS_GetListenAddress(node);
    if (!localAddr) {
        return DPS_ERR_INVALID;
    }
    regPut = calloc(1, sizeof(RegPut));
    if (!regPut) {
        return DPS_ERR_RESOURCES;
    }
    regPut->cb = cb;
    regPut->data = data;
    regPut->tenant = strndup(tenantString, DPS_MAX_TOPIC_STRLEN);
    if (!regPut->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    regPut->timeout = timeout;
    regPut->node = DPS_CreateNode("/", node->keyStore, node->signer.alg ? &node->signer.kid : NULL);
    if (!regPut->node || !regPut->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }

    ret = DPS_StartNode(regPut->node, DPS_MCAST_PUB_DISABLED, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        ret = BuildPutPayload(&regPut->payload, localAddr);
        if (ret == DPS_OK) {
            ret = DPS_Link(regPut->node, addrText, OnLinkedPut, regPut);
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

DPS_Status DPS_Registration_PutSyn(DPS_Node* node, const char* addrText, const char* tenantString,
                                   uint16_t timeout)
{
    DPS_Status ret;
    DPS_Event* event = DPS_CreateEvent();

    DPS_DBGTRACE();

    if (!event) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_Registration_Put(node, addrText, tenantString, timeout, OnPutComplete, event);
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
    const DPS_NodeAddress* localAddr;
    void* data;
    DPS_OnRegGetComplete cb;
    uv_timer_t timer;
    DPS_RegistrationList* regs;
    DPS_NodeAddress addr;
    int linked;
    DPS_Status status;
    uint16_t timeout;
} RegGet;

static void RegGetCB(RegGet* regGet)
{
    DPS_DBGTRACE();
    if (regGet->sub) {
        DPS_DestroySubscription(regGet->sub);
    }
    DPS_DestroyNode(regGet->node, OnNodeDestroyed, NULL);
    free(regGet->tenant);
    regGet->cb(regGet->regs, regGet->status, regGet->data);
    free(regGet);
}

static void OnGetUnlinkCB(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
    DPS_DBGTRACE();
    RegGetCB((RegGet*)data);
}

static void GetUnlink(RegGet* regGet)
{
    DPS_Status ret = DPS_OK;
    if (regGet->linked) {
        ret = DPS_Unlink(regGet->node, &regGet->addr, OnGetUnlinkCB, regGet);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("DPS_Unlink failed - %s\n", DPS_ErrTxt(ret));
        }
    }
    if (!regGet->linked || ret != DPS_OK) {
        RegGetCB(regGet);
    }
}

static void OnGetTimerClosed(uv_handle_t* handle)
{
    RegGet* regGet = (RegGet*)handle->data;
    regGet->status = DPS_OK;
    GetUnlink(regGet);
}

static void OnGetTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();
    uv_close((uv_handle_t*)timer, OnGetTimerClosed);
}

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    RegGet* regGet = (RegGet*)DPS_GetSubscriptionData(sub);

    DPS_DBGPRINT("OnPub regGet=%p\n", regGet);
    if (regGet) {
        DPS_Status ret;
        uint8_t count;
        DPS_RxBuffer buf;
        DPS_NodeAddress* addr = NULL;

        addr = DPS_CreateAddress();
        if (!addr) {
            DPS_ERRPRINT("Create address failed - %s\n", DPS_ERR_RESOURCES);
            return;
        }
        /*
         * Parse out the addresses from the payload
         */
        DPS_RxBufferInit(&buf, data, len);
        ret = CBOR_DecodeUint8(&buf, &count);
        if (ret == DPS_OK) {
            while (count--) {
                char* addrText;
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
                if (CBOR_DecodeString(&buf, &addrText, &len) != DPS_OK) {
                    break;
                }
                addrText = strndup(addrText, len);
                if (!addrText) {
                    break;
                }
                DPS_SetAddress(addr, addrText);
                if (!IsLocalAddr(addr, regGet->localAddr)) {
                    regGet->regs->list[regGet->regs->count].addrText = addrText;
                    ++regGet->regs->count;
                } else {
                    free(addrText);
                }
            }
        }
        DPS_DestroyAddress(addr);
    }
}

static void OnLinkedGet(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status ret, void* data)
{
    RegGet* regGet = (RegGet*)data;

    DPS_DBGTRACE();
    regGet->status = ret;
    if (regGet->status == DPS_OK) {
        const char* topics[2];
        DPS_CopyAddress(&regGet->addr, addr);
        /*
         * Subscribe to our tenant topic string
         */
        topics[0] = DPS_RegistryTopicString;
        topics[1] = regGet->tenant;
        regGet->sub = DPS_CreateSubscription(node, topics, 2);
        if (!regGet->sub) {
            regGet->status = DPS_ERR_RESOURCES;
        } else {
            DPS_SetSubscriptionData(regGet->sub, regGet);
            regGet->status = DPS_Subscribe(regGet->sub, OnPub);
            /*
             * Start a timer
             */
            if (regGet->status == DPS_OK) {
                int r;
                r = uv_timer_init(node->loop, &regGet->timer);
                if (!r) {
                    regGet->timer.data = regGet;
                    r = uv_timer_start(&regGet->timer, OnGetTimeout, regGet->timeout, 0);
                }
                if (r) {
                    regGet->status = DPS_ERR_FAILURE;
                }
            }
        }
    }
    if (regGet->status != DPS_OK) {
        GetUnlink(regGet);
    }
}

DPS_Status DPS_Registration_Get(DPS_Node* node, const char* addrText, const char* tenantString,
                                DPS_RegistrationList* regs, uint16_t timeout, DPS_OnRegGetComplete cb,
                                void* data)
{
    DPS_Status ret;
    RegGet* regGet;
    const DPS_NodeAddress* localAddr;

    DPS_DBGTRACE();

    if (!regs) {
        return DPS_ERR_NULL;
    }
    if (regs->size < 1) {
        return DPS_ERR_INVALID;
    }
    localAddr = DPS_GetListenAddress(node);
    if (!localAddr) {
        return DPS_ERR_INVALID;
    }
    /*
     * Clear candidate list
     */
    regGet = calloc(1, sizeof(RegGet));
    if (!regGet) {
        return DPS_ERR_RESOURCES;
    }
    regGet->localAddr = localAddr;
    regGet->cb = cb;
    regGet->data = data;
    regGet->regs = regs;
    regGet->regs->count = 0;
    regGet->timeout = timeout;
    regGet->tenant = strndup(tenantString, DPS_MAX_TOPIC_STRLEN);
    if (!regGet->tenant) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    regGet->node = DPS_CreateNode("/", node->keyStore, node->signer.alg ? &node->signer.kid : NULL);
    if (!regGet->node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_StartNode(regGet->node, DPS_MCAST_PUB_DISABLED, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
    } else {
        ret = DPS_Link(regGet->node, addrText, OnLinkedGet, regGet);
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

DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* addrText, const char* tenantString,
                                   DPS_RegistrationList* regs, uint16_t timeout)
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
    ret = DPS_Registration_Get(node, addrText, tenantString, regs, timeout, OnGetComplete, &getResult);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(getResult.event);
    }
    DPS_DestroyEvent(getResult.event);
    return ret;
}

typedef struct {
    void* data;
    DPS_OnRegLinkToComplete cb;
    size_t candidate;
    DPS_RegistrationList* regs;
} LinkTo;

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    LinkTo* linkTo = (LinkTo*)data;

    DPS_DBGTRACE();
    if (status == DPS_OK) {
        assert(addr);
        DPS_DBGPRINT("Candidate %d LINKED\n", linkTo->candidate);
        linkTo->regs->list[linkTo->candidate].flags = DPS_CANDIDATE_LINKED;
    } else {
        /*
         * Keep trying other registrations
         */
        DPS_DBGPRINT("Candidate %d FAILED\n", linkTo->candidate);
        linkTo->regs->list[linkTo->candidate].flags = DPS_CANDIDATE_FAILED;
        if (DPS_Registration_LinkTo(node, linkTo->regs, linkTo->cb, linkTo->data) == DPS_OK) {
            free(linkTo);
            return;
        }
    }
    linkTo->cb(node, linkTo->regs, addr, status, linkTo->data);
    free(linkTo);
}

static DPS_Status Link(DPS_Node* node, const char* addrText, LinkTo* linkTo)
{
    DPS_Status ret = DPS_ERR_NO_ROUTE;

    if (addrText) {
        if (IsLocalAddrText(addrText, DPS_GetListenAddress(node))) {
            DPS_DBGPRINT("Candidate %d INVALID\n", linkTo->candidate);
            linkTo->regs->list[linkTo->candidate].flags = DPS_CANDIDATE_FAILED;
        } else {
            ret = DPS_Link(node, addrText, OnLinked, linkTo);
        }
    }
    return ret;
}

DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_RegistrationList* regs,
                                   DPS_OnRegLinkToComplete cb, void* data)
{
    DPS_Status ret = DPS_ERR_NO_ROUTE;
    size_t i;
    int untried = 0;

    DPS_DBGTRACE();

    /*
     * Check there is at least one candidate that hasn't been tried yet
     */
    for (i = 0; i < regs->count; ++i) {
        if (regs->list[i].flags == 0) {
            ++untried;
        }
    }
    DPS_DBGPRINT("LinkTo untried=%d\n", untried);
    while (untried) {
        uint32_t r = DPS_Rand() % regs->count;
        if (regs->list[r].flags == 0) {
            LinkTo* linkTo = malloc(sizeof(LinkTo));
            if (linkTo) {
                linkTo->cb = cb;
                linkTo->data = data;
                linkTo->regs = regs;
                linkTo->candidate = r;

                regs->list[r].flags = DPS_CANDIDATE_TRYING;
                DPS_DBGPRINT("Candidate %d TRYING\n", linkTo->candidate);
                ret = DPS_OK;
            } else {
                ret = DPS_ERR_RESOURCES;
            }
            if (ret == DPS_OK) {
                ret = Link(node, regs->list[r].addrText, linkTo);
            }
            if (ret == DPS_OK) {
                break;
            }
            DPS_DBGPRINT("Candidate %d FAILED %s\n", linkTo->candidate, DPS_ErrTxt(ret));
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

static void OnRegLinkTo(DPS_Node* node, DPS_RegistrationList* regs, const DPS_NodeAddress* addr,
                        DPS_Status status, void* data)
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

    DPS_DBGTRACE();

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
    DPS_RegistrationList* regs;

    DPS_DBGTRACE();

    regs = calloc(1, sizeof(DPS_RegistrationList) + (size - 1) * sizeof(DPS_Registration));
    if (regs) {
        regs->size = size;
    }
    return regs;
}

void DPS_DestroyRegistrationList(DPS_RegistrationList* regs)
{
    DPS_DBGTRACE();

    if (regs) {
        while (regs->size--) {
            if (regs->list[regs->size].addrText) {
                free(regs->list[regs->size].addrText);
            }
        }
        free(regs);
    }
}
