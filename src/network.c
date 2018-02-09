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
#include <ws2ipdef.h>
#include <mstcpip.h>
#endif

#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

const char* DPS_NetAddrText(const struct sockaddr* addr)
{
    if (addr) {
        char name[INET6_ADDRSTRLEN];
        static char txt[sizeof(name) + 8];
        uint16_t port;
        int ret;
        if (addr->sa_family == AF_INET6) {
            ret = uv_ip6_name((const struct sockaddr_in6*)addr, name, sizeof(name));
            port = ((const struct sockaddr_in6*)addr)->sin6_port;
            if (strcmp(name, "::ffff:127.0.0.1") == 0 || strcmp(name, "::1") == 0) {
                strncpy_s(name, INET6_ADDRSTRLEN, "<localhost>", sizeof(name));
            }
        } else {
            ret = uv_ip4_name((const struct sockaddr_in*)addr, name, sizeof(name));
            port = ((const struct sockaddr_in*)addr)->sin_port;
            if (strcmp(name, "127.0.0.1") == 0) {
                strncpy_s(name, INET6_ADDRSTRLEN, "<localhost>", sizeof(name));
            }
        }
        if (ret) {
            return "Invalid address";
        }
        /*
         * Make sure name is NUL terminated
         */
        name[sizeof(name) - 1] = 0;
        snprintf(txt, sizeof(txt), "%s/%d", name, ntohs(port));
        return txt;
    } else {
        return "NULL";
    }
}

static const uint8_t IP4as6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

int DPS_SameAddr(const DPS_NodeAddress* addr1, const DPS_NodeAddress* addr2)
{
    const struct sockaddr* a = (const struct sockaddr*)&addr1->inaddr;
    const struct sockaddr* b = (const struct sockaddr*)&addr2->inaddr;
    struct sockaddr_in6 tmp;

    if (a->sa_family != b->sa_family) {
        uint32_t ip;
        if (a->sa_family == AF_INET6) {
            const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
            ip = ipb->sin_addr.s_addr;
            tmp.sin6_port = ipb->sin_port;
            b = (const struct sockaddr*)&tmp;
        } else {
            const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
            ip = ipa->sin_addr.s_addr;
            tmp.sin6_port = ipa->sin_port;
            a = (const struct sockaddr*)&tmp;
        }
        memcpy_s(&tmp.sin6_addr, sizeof(tmp.sin6_addr), IP4as6, 12);
        memcpy_s((uint8_t*)&tmp.sin6_addr + 12, sizeof(tmp.sin6_addr) - 12, &ip, 4);
        tmp.sin6_family = AF_INET6;
    }
    if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6) {
        const struct sockaddr_in6* ip6a = (const struct sockaddr_in6*)a;
        const struct sockaddr_in6* ip6b = (const struct sockaddr_in6*)b;
        return (ip6a->sin6_port == ip6b->sin6_port) && (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
    } else if (a->sa_family == AF_INET && b->sa_family == AF_INET) {
        const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
        const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
        return (ipa->sin_port == ipb->sin_port) && (ipa->sin_addr.s_addr == ipb->sin_addr.s_addr);
    } else {
        return DPS_FALSE;
    }
}

DPS_NodeAddress* DPS_SetAddress(DPS_NodeAddress* addr, const struct sockaddr* sa)
{
    memzero_s(addr, sizeof(DPS_NodeAddress));
    if (sa) {
        if (sa->sa_family == AF_INET) {
            memcpy_s(&addr->inaddr, sizeof(addr->inaddr), sa, sizeof(struct sockaddr_in));
        } else if (sa->sa_family == AF_INET6) {
            memcpy_s(&addr->inaddr, sizeof(addr->inaddr), sa, sizeof(struct sockaddr_in6));
        }
    }
    return addr;
}

void DPS_EndpointSetPort(DPS_NetEndpoint* ep, uint16_t port)
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
#ifdef _WIN32
    /* Windows requires that v4 addresses are mapped to v6 addresses for dual stack sockets */
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
