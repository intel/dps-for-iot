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

/* These must be included in this order before uv.h */
#include <safe_lib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#define EAI_ADDRFAMILY WSAEAFNOSUPPORT
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "compat.h"
#include "node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

const char* DPS_NetAddrText(const struct sockaddr* addr)
{
    if (addr) {
        const char* fmt;
        char name[INET6_ADDRSTRLEN];
        static THREAD char txt[DPS_NODE_ADDRESS_MAX_STRING_LEN];
        uint16_t port;
        int ret;
        if (addr->sa_family == AF_INET6) {
            ret = uv_ip6_name((const struct sockaddr_in6*)addr, name, sizeof(name));
            port = ((const struct sockaddr_in6*)addr)->sin6_port;
            fmt = "[%s]:%d";
        } else {
            ret = uv_ip4_name((const struct sockaddr_in*)addr, name, sizeof(name));
            port = ((const struct sockaddr_in*)addr)->sin_port;
            fmt = "%s:%d";
        }
        if (ret) {
            return "Invalid address";
        }
        /*
         * Make sure name is NUL terminated
         */
        name[sizeof(name) - 1] = 0;
        snprintf(txt, sizeof(txt), fmt, name, ntohs(port));
        return txt;
    } else {
        return "NULL";
    }
}

uint16_t DPS_NetAddrPort(const struct sockaddr* addr)
{
    const struct sockaddr_storage* ss = (const struct sockaddr_storage*)addr;
    uint16_t port = 0;
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6* ip6 = (const struct sockaddr_in6*)addr;
        port = ntohs(ip6->sin6_port);
    } else {
        const struct sockaddr_in* ip4 = (const struct sockaddr_in*)addr;
        port = ntohs(ip4->sin_port);
    }
    return port;
}

DPS_NodeAddress* DPS_NetSetAddr(DPS_NodeAddress* addr, DPS_NodeAddressType type,
                                const struct sockaddr* sa)
{
    memzero_s(addr, sizeof(DPS_NodeAddress));
    addr->type = type;
    if (sa) {
        if (sa->sa_family == AF_INET) {
            memcpy_s(&addr->u.inaddr, sizeof(addr->u.inaddr), sa, sizeof(struct sockaddr_in));
        } else if (sa->sa_family == AF_INET6) {
            memcpy_s(&addr->u.inaddr, sizeof(addr->u.inaddr), sa, sizeof(struct sockaddr_in6));
        }
    }
    return addr;
}

static const uint8_t IP4as6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

int DPS_SameAddr(const DPS_NodeAddress* addr1, const DPS_NodeAddress* addr2)
{
    const struct sockaddr* a = (const struct sockaddr*)&addr1->u.inaddr;
    const struct sockaddr* b = (const struct sockaddr*)&addr2->u.inaddr;
    struct sockaddr_in6 tmp;

    if (addr1->type != addr2->type) {
        return DPS_FALSE;
    }
    switch (addr1->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (a->sa_family != b->sa_family) {
            uint32_t ip;
            tmp.sin6_family = AF_INET6;
            if (a->sa_family == AF_INET6) {
                const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
                tmp.sin6_port = ipb->sin_port;
                ip = ipb->sin_addr.s_addr;
            } else {
                const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
                tmp.sin6_port = ipa->sin_port;
                ip = ipa->sin_addr.s_addr;
            }
            memcpy_s(&tmp.sin6_addr, sizeof(tmp.sin6_addr), IP4as6, 12);
            memcpy_s((uint8_t*)&tmp.sin6_addr + 12, sizeof(tmp.sin6_addr) - 12, &ip, 4);
            if (a->sa_family == AF_INET6) {
                b = (const struct sockaddr*)&tmp;
            } else {
                a = (const struct sockaddr*)&tmp;
            }
        }
        if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6) {
            const struct sockaddr_in6* ip6a = (const struct sockaddr_in6*)a;
            const struct sockaddr_in6* ip6b = (const struct sockaddr_in6*)b;
            return (ip6a->sin6_port == ip6b->sin6_port) &&
                (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
        } else if (a->sa_family == AF_INET && b->sa_family == AF_INET) {
            const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
            const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
            return (ipa->sin_port == ipb->sin_port) && (ipa->sin_addr.s_addr == ipb->sin_addr.s_addr);
        }
        return DPS_FALSE;
    case DPS_PIPE:
        return !strcmp(addr1->u.path, addr2->u.path);
    default:
        return DPS_FALSE;
    }
}

DPS_Status DPS_SplitAddress(const char* addrText, char* host, size_t hostLen,
                            char* service, size_t serviceLen)
{
    const char *src = addrText;
    const char *end;
    char *dst;

    DPS_DBGTRACE();

    if (!host || !hostLen || !service || !serviceLen) {
        return DPS_ERR_ARGS;
    }
    host[0] = 0;
    service[0] = 0;

    /*
     * Parse host
     */
    enum {
          BEGIN,
          IPV4_BEGIN,
          IPV6_BEGIN,
          IPV6_END,
          END
    } hostState = BEGIN;
    dst = host;
    end = &host[hostLen];
    while (*src && (dst < end)) {
        switch (hostState) {
        case BEGIN:
            if (*src == '[') {
                src++;
                hostState = IPV6_BEGIN;
            } else {
                hostState = IPV4_BEGIN;
            }
            break;
        case IPV6_BEGIN:
            if (*src == ']') {
                src++;
                hostState = IPV6_END;
            } else {
                *dst++ = *src++;
            }
            break;
        case IPV6_END:
            if (*src == ':') {
                src++;
                hostState = END;
            } else {
                return DPS_ERR_INVALID;
            }
            break;
        case IPV4_BEGIN:
            if (*src == ':') {
                src++;
                hostState = END;
            } else {
                *dst++ = *src++;
            }
            break;
        case END:
            goto Done;
        }
    }
 Done:
    if (dst == end) {
        return DPS_ERR_OVERFLOW;
    }
    *dst = 0;
    /*
     * Parse service
     */
    dst = service;
    end = &service[serviceLen];
    while (*src && (dst < end)) {
        *dst++ = *src++;
    }
    if (dst == end) {
        return DPS_ERR_OVERFLOW;
    }
    *dst = 0;
    return DPS_OK;
}

/*
 * This is here for a few reasons:
 * 1. uv_inet_pton() will ignore scope IDs, so is not suitable for
 *    link-local IPv6 addresses.
 * 2. uv_getaddrinfo() provides a synchronous version, but still
 *    requires a uv_loop_t argument which we don't have or need in
 *    DPS_SetAddress().
 * 3. IPv6 any (::) or localhost (::1) will not work on an IPv4-only
 *    host.
 */
static DPS_Status GetScope(const char* host, const char* service, struct sockaddr_storage* inaddr)
{
    struct addrinfo hints;
    struct addrinfo *ai = NULL;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_ADDRCONFIG;
    err = getaddrinfo(host, service, &hints, &ai);
    if ((err == EAI_ADDRFAMILY) && host) {
        /*
         * Try again with the other address family for localhost
         */
        if (!strcmp(host, "::1")) {
            err = getaddrinfo("127.0.0.1", service, &hints, &ai);
        } else if (!strcmp(host, "127.0.0.1")) {
            err = getaddrinfo("::1", service, &hints, &ai);
        } else if (!strcmp(host, "::")) {
            err = getaddrinfo("0.0.0.0", service, &hints, &ai);
        } else if (!strcmp(host, "0.0.0.0")) {
            err = getaddrinfo("::", service, &hints, &ai);
        }
    }
    if (err) {
        DPS_ERRPRINT("getaddrinfo failed: %s\n", gai_strerror(err));
        return DPS_ERR_NETWORK;
    }
    switch (ai->ai_family) {
    case AF_INET:
        memcpy(inaddr, ai->ai_addr, sizeof(struct sockaddr_in));
        break;
    case AF_INET6:
        memcpy(inaddr, ai->ai_addr, sizeof(struct sockaddr_in6));
        break;
    default:
        err = 1;
        break;
    }
    freeaddrinfo(ai);
    return err ? DPS_ERR_NETWORK : DPS_OK;
}

DPS_NodeAddress* DPS_SetAddress(DPS_NodeAddress* addr, const char* addrText)
{
    char host[DPS_MAX_HOST_LEN + 1];
    char service[DPS_MAX_SERVICE_LEN + 1];
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!addr || !addrText) {
        goto ErrorExit;
    }

    memset(addr, 0, sizeof(DPS_NodeAddress));
#if defined(DPS_USE_DTLS)
    addr->type = DPS_DTLS;
#elif defined(DPS_USE_TCP)
    addr->type = DPS_TCP;
#elif defined(DPS_USE_UDP)
    addr->type = DPS_UDP;
#elif defined(DPS_USE_PIPE)
    addr->type = DPS_PIPE;
#endif
    switch (addr->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        ret = DPS_SplitAddress(addrText, host, sizeof(host), service, sizeof(service));
        if (ret != DPS_OK) {
            goto ErrorExit;
        }
        ret = GetScope(host, service, &addr->u.inaddr);
        if (ret != DPS_OK) {
            goto ErrorExit;
        }
        return addr;
    case DPS_PIPE:
        strncpy(addr->u.path, addrText, DPS_NODE_ADDRESS_PATH_MAX - 1);
        return addr;
    default:
        break;
    }

ErrorExit:
    DPS_ERRPRINT("Invalid address %s\n", addrText);
    return NULL;
}

DPS_Status DPS_GetLoopbackAddress(DPS_NodeAddress* addr, DPS_Node* node)
{
    DPS_Status ret;
    char service[8];

    DPS_CopyAddress(addr, DPS_GetListenAddress(node));
    switch (addr->type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        snprintf(service, sizeof(service), "%d",
                 ntohs(((struct sockaddr_in*)(&addr->u.inaddr))->sin_port));
        ret = GetScope(NULL, service, &addr->u.inaddr);
        if (ret != DPS_OK) {
            break;
        }
        break;
    default:
        ret = DPS_OK;
        break;
    }
    return ret;
}

void DPS_EndpointSetPort(DPS_NetEndpoint* ep, uint16_t port)
{
    switch (ep->addr.type) {
    case DPS_DTLS:
    case DPS_TCP:
    case DPS_UDP:
        if (!ep->cn) {
            port = htons(port);
            if (ep->addr.u.inaddr.ss_family == AF_INET6) {
                struct sockaddr_in6* ip6 = (struct sockaddr_in6*)&ep->addr.u.inaddr;
                ip6->sin6_port = port;
            } else {
                struct sockaddr_in* ip4 = (struct sockaddr_in*)&ep->addr.u.inaddr;
                ip4->sin_port = port;
            }
        }
        break;
    default:
        assert(ep->cn);
        break;
    }
}

void DPS_EndpointSetPath(DPS_NetEndpoint* ep, char* path, size_t pathLen)
{
    switch (ep->addr.type) {
    case DPS_UDP:
    case DPS_PIPE:
        ep->addr.type = DPS_PIPE;
        assert(pathLen < DPS_NODE_ADDRESS_PATH_MAX);
        memcpy(ep->addr.u.path, path, pathLen);
        ep->addr.u.path[pathLen] = 0;
        break;
    default:
        break;
    }
}

void DPS_NetFreeBufs(uv_buf_t* bufs, size_t numBufs)
{
    while (numBufs--) {
        if (bufs->base) {
            free(bufs->base);
        }
        ++bufs;
    }
}

void DPS_MapAddrToV6(struct sockaddr* addr)
{
    /* Windows requires that v4 addresses are mapped to v6 addresses for dual stack sockets */
#if defined(__MINGW64__)
    if (addr->sa_family == AF_INET) {
        static const IN6_ADDR v4mappedprefix = {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }};
        struct in_addr inaddr = ((PSOCKADDR_IN)addr)->sin_addr;
        SCOPE_ID scope = { 0 };
        USHORT port = ((PSOCKADDR_IN)addr)->sin_port;
        memset(addr, 0, sizeof(struct sockaddr_storage));
        PSOCKADDR_IN6 a6 = (struct sockaddr_in6 *)addr;
        const PIN_ADDR a4 = &inaddr;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = port;
        a6->sin6_flowinfo = 0;
        a6->sin6_addr = v4mappedprefix;
        memcpy(&a6->sin6_addr.s6_bytes[12], a4, 4);
        a6->sin6_scope_struct = scope;
    }
#elif defined(_MSC_VER)
    if (addr->sa_family == AF_INET) {
        struct in_addr inaddr = *(struct in_addr*)INETADDR_ADDRESS(addr);
        SCOPE_ID scope = INETADDR_SCOPE_ID(addr);
        USHORT port = INETADDR_PORT(addr);
        memset(addr, 0, sizeof(struct sockaddr_storage));
        IN6ADDR_SETV4MAPPED((struct sockaddr_in6 *)addr, &inaddr, scope, port);
    }
#else
    /* Linux does not require mapping v4 addresses to v6 addresses for dual stack sockets */
#endif
}

static DPS_NetRxBuffer* AllocNetRxBufferHandler(size_t len)
{
    return (DPS_NetRxBuffer*)malloc(len);
}

static void FreeNetRxBufferHandler(DPS_NetRxBuffer* buf)
{
    free(buf);
}

static DPS_AllocNetRxBufferHandler allocNetRxBufferHandler = AllocNetRxBufferHandler;
static DPS_FreeNetRxBufferHandler freeNetRxBufferHandler = FreeNetRxBufferHandler;

void DPS_SetNetRxBufferHandlers(DPS_AllocNetRxBufferHandler allocHandler,
                                DPS_FreeNetRxBufferHandler freeHandler)
{
    allocNetRxBufferHandler = allocHandler;
    freeNetRxBufferHandler = freeHandler;
}

DPS_NetRxBuffer* DPS_CreateNetRxBuffer(size_t len)
{
    DPS_NetRxBuffer* buf = NULL;

    buf = allocNetRxBufferHandler(sizeof(DPS_NetRxBuffer) + len - 1);
    if (!buf) {
        return NULL;
    }
    DPS_RxBufferInit(&buf->rx, buf->data, len);
    buf->refCount = 1;
    return buf;
}

void DPS_NetRxBufferIncRef(DPS_NetRxBuffer* buf)
{
    if (buf) {
        ++buf->refCount;
    }
}

void DPS_NetRxBufferDecRef(DPS_NetRxBuffer* buf)
{
    if (buf) {
        assert(buf->refCount > 0);
        if (--buf->refCount == 0) {
            freeNetRxBufferHandler(buf);
        }
    }
}
