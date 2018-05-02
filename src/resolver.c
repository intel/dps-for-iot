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
#include <string.h>
#include <malloc.h>
#include <safe_lib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include "resolver.h"
#include "node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define MAX_HOST_LEN    256  /* Per RFC 1034/1035 */
#define MAX_SERVICE_LEN  16  /* Per RFC 6335 section 5.1 */

typedef struct _ResolverInfo {
    DPS_Node* node;
    DPS_OnResolveAddressComplete cb;
    void* data;
    uv_getaddrinfo_t info;
    char host[MAX_HOST_LEN + 1];
    char service[MAX_SERVICE_LEN + 1];
    struct  _ResolverInfo* next;
} ResolverInfo;

static void GetAddrInfoCB(uv_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    ResolverInfo* resolver = (ResolverInfo*)req->data;

    if (status == 0) {
        DPS_NodeAddress addr;
        if (res->ai_family == AF_INET6) {
            memcpy_s(&addr.inaddr, sizeof(addr.inaddr), res->ai_addr, sizeof(struct sockaddr_in6));
        } else {
            memcpy_s(&addr.inaddr, sizeof(addr.inaddr), res->ai_addr, sizeof(struct sockaddr_in));
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
        r = uv_getaddrinfo(async->loop, &resolver->info, GetAddrInfoCB, resolver->host, resolver->service, NULL);
        if (r) {
            DPS_ERRPRINT("uv_getaddrinfo call error %s\n", uv_err_name(r));
            resolver->cb(resolver->node, NULL, resolver->data);
            free(resolver);
        }
    }

    DPS_UnlockNode(node);
}

DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service, DPS_OnResolveAddressComplete cb, void* data)
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
