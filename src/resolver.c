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

typedef struct _ResolverRequest {
    DPS_Queue queue;
    DPS_Node* node;
    DPS_OnResolveAddressComplete cb;
    void* data;
    uv_getaddrinfo_t info;
    DPS_NodeAddressType network;
    char host[DPS_MAX_HOST_LEN + 1];
    char service[DPS_MAX_SERVICE_LEN + 1];
} ResolverRequest;

static void GetAddrInfoCB(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    ResolverRequest* resolver = (ResolverRequest*)req->data;

    if (status == 0) {
        DPS_NodeAddress addr;
        addr.type = resolver->network;
        if (res->ai_family == AF_INET6) {
            memcpy_s(&addr.u.inaddr, sizeof(addr.u.inaddr), res->ai_addr, sizeof(struct sockaddr_in6));
        } else {
            memcpy_s(&addr.u.inaddr, sizeof(addr.u.inaddr), res->ai_addr, sizeof(struct sockaddr_in));
        }
        resolver->cb(resolver->node, &addr, resolver->data);
        uv_freeaddrinfo(res);
    } else {
        DPS_ERRPRINT("uv_getaddrinfo failed %s\n", uv_err_name(status));
        resolver->cb(resolver->node, NULL, resolver->data);
    }
    free(resolver);
}

static void TryGetAddrInfoCB(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    ResolverRequest* resolver = (ResolverRequest*)req->data;

    if (status == UV_EAI_ADDRFAMILY) {
        /*
         * Try again with the other address family for localhost
         */
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG;
        if (!strcmp(resolver->host, "::1")) {
            status = uv_getaddrinfo(req->loop, &resolver->info, GetAddrInfoCB, "127.0.0.1",
                                    resolver->service, &hints);
        } else if (!strcmp(resolver->host, "127.0.0.1")) {
            status = uv_getaddrinfo(req->loop, &resolver->info, GetAddrInfoCB, "::1",
                                    resolver->service, &hints);
        } else if (!strcmp(resolver->host, "::")) {
            status = uv_getaddrinfo(req->loop, &resolver->info, GetAddrInfoCB, "0.0.0.0",
                                    resolver->service, &hints);
        } else if (!strcmp(resolver->host, "0.0.0.0")) {
            status = uv_getaddrinfo(req->loop, &resolver->info, GetAddrInfoCB, "::",
                                    resolver->service, &hints);
        }
        if (status == 0) {
            return;
        }
    }
    GetAddrInfoCB(req, status, res);
}

void DPS_AsyncResolveAddress(uv_async_t* async)
{
    DPS_Node* node = (DPS_Node*)async->data;

    DPS_DBGTRACE();

    DPS_LockNode(node);

    while (!DPS_QueueEmpty(&node->resolverQueue)) {
        int r;
        struct addrinfo hints;
        ResolverRequest* resolver = (ResolverRequest*)DPS_QueueFront(&node->resolverQueue);
        DPS_QueueRemove(&resolver->queue);

        if (node->state != DPS_NODE_RUNNING) {
            resolver->cb(resolver->node, NULL, resolver->data);
            free(resolver);
            continue;
        }
        resolver->info.data = resolver;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG;
        r = uv_getaddrinfo(async->loop, &resolver->info, TryGetAddrInfoCB, resolver->host,
                           resolver->service, &hints);
        if (r) {
            DPS_ERRPRINT("uv_getaddrinfo call error %s\n", uv_err_name(r));
            resolver->cb(resolver->node, NULL, resolver->data);
            free(resolver);
        }
    }

    DPS_UnlockNode(node);
}

DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* network, const char* host, const char* service,
                              DPS_OnResolveAddressComplete cb, void* data)
{
    DPS_Status ret;
    ResolverRequest* resolver;

    DPS_DBGTRACE();

    if (!node->loop) {
        DPS_ERRPRINT("Cannot resolve address - node has not been started\n");
        return DPS_ERR_INVALID;
    }
    if (!service || !cb) {
        return DPS_ERR_NULL;
    }
    /*
     * Resolve NULL or "any" address to localhost so it is a usable
     * destination.
     */
    if (!host || !strcmp(host, "0.0.0.0") || !strcmp(host, "::")) {
        host = "::1";
    }
    resolver = calloc(1, sizeof(ResolverRequest));
    if (!resolver) {
        return DPS_ERR_RESOURCES;
    }
    resolver->network = DPS_NetAddressType(network);
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
        DPS_QueuePushBack(&node->resolverQueue, &resolver->queue);
        ret = DPS_OK;
    }
    DPS_UnlockNode(node);
    return ret;
}
