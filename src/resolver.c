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
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include "node.h"
#include "resolver.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _ResolverInfo {
    DPS_Node* node;
    DPS_OnResolveAddressComplete cb;
    void* data;
    uv_getaddrinfo_t info;
    char host[DPS_MAX_HOST_LEN + 1];
    char service[DPS_MAX_SERVICE_LEN + 1];
    struct  _ResolverInfo* next;
} ResolverInfo;

static void GetAddrInfoCB(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    ResolverInfo* resolver = (ResolverInfo*)req->data;

    if (status == 0) {
        DPS_NodeAddress addr;
#if defined(DPS_USE_DTLS)
        addr.type = DPS_DTLS;
#elif defined(DPS_USE_TCP)
        addr.type = DPS_TCP;
#elif defined(DPS_USE_UDP)
        addr.type = DPS_UDP;
#endif
        /*
         * Resolve "any" address to loopback so it is a usable
         * destination.
         */
        if (res->ai_family == AF_INET6) {
            struct sockaddr_in6* saddr = (struct sockaddr_in6*)&addr.u.inaddr;
            memcpy_s(&addr.u.inaddr, sizeof(addr.u.inaddr), res->ai_addr, sizeof(struct sockaddr_in6));
            if (!memcmp(&saddr->sin6_addr, &in6addr_any, sizeof(struct in6_addr))) {
                memcpy(&saddr->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));
            }
        } else {
            struct sockaddr_in* saddr = (struct sockaddr_in*)&addr.u.inaddr;
            memcpy_s(&addr.u.inaddr, sizeof(addr.u.inaddr), res->ai_addr, sizeof(struct sockaddr_in));
            if (saddr->sin_addr.s_addr == htonl(INADDR_ANY)) {
                saddr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            }
        }
        resolver->cb(resolver->node, &addr, resolver->data);
        uv_freeaddrinfo(res);
    } else {
        DPS_ERRPRINT("uv_getaddrinfo failed %s\n", uv_err_name(status));
        resolver->cb(resolver->node, NULL, resolver->data);
    }
    free(resolver);
}

void DPS_AsyncResolveAddress(uv_async_t* async)
{
    DPS_Node* node = (DPS_Node*)async->data;

    DPS_DBGTRACE();

    DPS_LockNode(node);

    while (node->resolverList) {
        int r;
        ResolverInfo* resolver = node->resolverList;
        node->resolverList = resolver->next;

        if (node->state != DPS_NODE_RUNNING) {
            resolver->cb(resolver->node, NULL, resolver->data);
            free(resolver);
            continue;
        }
        resolver->info.data = resolver;
        r = uv_getaddrinfo(async->loop, &resolver->info, GetAddrInfoCB, resolver->host,
                           resolver->service, NULL);
        if (r) {
            DPS_ERRPRINT("uv_getaddrinfo call error %s\n", uv_err_name(r));
            resolver->cb(resolver->node, NULL, resolver->data);
            free(resolver);
        }
    }

    DPS_UnlockNode(node);
}

DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service,
                              DPS_OnResolveAddressComplete cb, void* data)
{
    DPS_Status ret;
    ResolverInfo* resolver;

    DPS_DBGTRACE();

    if (!node->loop) {
        DPS_ERRPRINT("Cannot resolve address - node has not been started\n");
        return DPS_ERR_INVALID;
    }
    if (!service || !cb) {
        return DPS_ERR_NULL;
    }
    if (!host) {
        host = "localhost";
    }
    resolver = calloc(1, sizeof(ResolverInfo));
    if (!resolver) {
        return DPS_ERR_RESOURCES;
    }
    strncpy_s(resolver->host, sizeof(resolver->host), host, sizeof(resolver->host) - 1);
    strncpy_s(resolver->service, sizeof(resolver->service), service, sizeof(resolver->service) - 1);
    resolver->node = node;
    resolver->cb = cb;
    resolver->data = data;

    DPS_LockNode(node);
    /*
     * We are holding the node lock so we can link the resolver
     * after we have confirmed the async_send was sucessful.
     */
    if (uv_async_send(&node->resolverAsync)) {
        free(resolver);
        ret = DPS_ERR_FAILURE;
    } else {
        resolver->next = node->resolverList;
        node->resolverList = resolver;
        ret = DPS_OK;
    }
    DPS_UnlockNode(node);
    return ret;
}
