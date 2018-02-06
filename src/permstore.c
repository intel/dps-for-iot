/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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

#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include "cose.h"
#include "node.h"
#include "topics.h"

#include <stdlib.h>
#include <string.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

const DPS_KeyId* DPS_GetNetworkId(DPS_PermissionStoreRequest* request)
{
    return request->netId;
}

const DPS_KeyId* DPS_GetEndToEndId(DPS_PermissionStoreRequest* request)
{
    return request->signerId;
}

DPS_Permission DPS_GetPermission(DPS_PermissionStoreRequest* request)
{
    return request->perm;
}

DPS_Status DPS_IncludesTopics(DPS_PermissionStoreRequest* request, const char** topics, size_t numTopics)
{
    DPS_BitVector* tmp = NULL;
    DPS_Status ret;
    size_t i;

    if (!request->bf) {
        ret = DPS_ERR_MISSING;
        goto Exit;
    }
    tmp = DPS_BitVectorAlloc();
    if (!tmp) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
    }
    for (i = 0; i < numTopics; ++i) {
        if (DPS_AddTopic(tmp, topics[i], request->separators, DPS_SubTopic) != DPS_OK) {
            ret = DPS_ERR_FAILURE;
            goto Exit;
        }
    }
    ret = DPS_BitVectorIncludes(request->bf, tmp) ? DPS_OK : DPS_ERR_FAILURE;
Exit:
    DPS_BitVectorFree(tmp);
    return ret;
}

DPS_PermissionStore* DPS_PermissionStoreHandle(DPS_PermissionStoreRequest* request)
{
    return request->permStore;
}

DPS_PermissionStore* DPS_CreatePermissionStore(DPS_PermissionHandler handler)
{
    DPS_DBGTRACE();

    DPS_PermissionStore* permStore = calloc(1, sizeof(DPS_PermissionStore));
    if (permStore) {
        permStore->handler = handler;
    }
    return permStore;
}

void DPS_DestroyPermissionStore(DPS_PermissionStore* permStore)
{
    DPS_DBGTRACE();

    if (!permStore) {
        return;
    }
    free(permStore);
}

DPS_Status DPS_SetPermissionStoreData(DPS_PermissionStore* permStore, void* data)
{
    if (permStore) {
        permStore->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetPermissionStoreData(const DPS_PermissionStore* permStore)
{
    return permStore ? permStore->userData : NULL;
}

int DPS_RequestPermission(DPS_Node* node, DPS_NetEndpoint* ep, uint8_t* encryptedBytes, size_t numBytes,
                          DPS_Permission perm, DPS_BitVector* bf)
{
    DPS_PermissionStoreRequest request;
    DPS_RxBuffer buf;
    DPS_KeyId netId;
    COSE_Entity signer;
    int ret;

    DPS_DBGTRACE();

    switch (perm) {
    case DPS_PERM_PUB: DPS_DBGPRINT("Request PUB permission\n"); break;
    case DPS_PERM_SUB: DPS_DBGPRINT("Request SUB permission\n"); break;
    case DPS_PERM_ACK: DPS_DBGPRINT("Request ACK permission\n"); break;
    default: break;
    }

    memset(&request, 0, sizeof(request));
    request.permStore = node->permStore;
    DPS_DBGPRINT("Network ID\n");
    if (DPS_NetId(&netId, ep) == DPS_OK) {
        request.netId = &netId;
        DPS_DBGBYTES(netId.id, netId.len);
    }
    DPS_DBGPRINT("End-to-end ID\n");
    if (encryptedBytes && numBytes) {
        DPS_RxBufferInit(&buf, encryptedBytes, numBytes);
        if (COSE_Verify(&buf, node->keyStore, &signer) == DPS_OK) {
            request.signerId = &signer.kid;
            DPS_DBGBYTES(signer.kid.id, signer.kid.len);
        }
    }
    request.perm = perm;
    if (bf) {
        request.separators = node->separators;
        request.bf = bf;
    }
    if (node->permStore) {
        ret = node->permStore->handler(&request);
    } else {
        ret = DPS_TRUE;
    }
    DPS_DBGPRINT("%s\n", (ret == DPS_TRUE) ? "Authorized" : "Denied");
    return ret;
}

typedef struct _Access {
    DPS_KeyId *id;
    DPS_Permission perms;
    struct _Access* next;
} Access;

typedef struct _PermissionEntry {
    char** topics;
    size_t numTopics;
    Access* access;
    struct _PermissionEntry* next;
} PermissionEntry;

struct _DPS_MemoryPermissionStore {
    DPS_PermissionStore permStore;
    PermissionEntry* entries;
};

static int MemoryPermissionStoreHandler(DPS_PermissionStoreRequest* request)
{
    DPS_MemoryPermissionStore* permStore = (DPS_MemoryPermissionStore*)DPS_PermissionStoreHandle(request);
    DPS_Permission perm;
    const DPS_KeyId* endToEndId;
    const DPS_KeyId* networkId;
    PermissionEntry* entry;
    Access* access;
    const DPS_KeyId* id;
    DPS_Status ret;

    perm = DPS_GetPermission(request);
    endToEndId = DPS_GetEndToEndId(request);
    networkId = DPS_GetNetworkId(request);

    for (entry = permStore->entries; entry; entry = entry->next) {
        /*
         * Check topics
         */
        if (entry->numTopics) {
            ret = DPS_IncludesTopics(request, (const char**)entry->topics, entry->numTopics);
            /*
             * Topic information for acknowledgements is only present at end nodes.
             */
            if (perm == DPS_PERM_ACK) {
                if ((ret != DPS_OK) && (ret != DPS_ERR_MISSING)) {
                    continue;
                }
            } else if (ret != DPS_OK) {
                continue;
            }
        }
        /*
         * Check identity.  Publications and acknowledgements include
         * an end-to-end ID while subscriptions only include a network
         * ID.  Forwarding access looks only at network ID.
         */
        switch (perm) {
        case DPS_PERM_PUB:
        case DPS_PERM_ACK:
            id = endToEndId;
            break;
        case DPS_PERM_SUB:
            id = networkId;
            break;
        default:
            id = NULL;
            break;
        }
        for (access = entry->access; access; access = access->next) {
            if (access->id) {
                if ((access->perms & DPS_PERM_FORWARD) && !DPS_SameKeyId(networkId, access->id)) {
                    continue;
                } else if (!DPS_SameKeyId(id, access->id)) {
                    continue;
                }
            }
            /*
             * Check permission
             */
            if ((perm & access->perms) == 0) {
                continue;
            }
            return DPS_TRUE;
        }
    }
    return DPS_FALSE;
}

DPS_MemoryPermissionStore* DPS_CreateMemoryPermissionStore()
{
    DPS_MemoryPermissionStore* permStore;

    DPS_DBGTRACE();

    permStore = calloc(1, sizeof(DPS_MemoryPermissionStore));
    if (!permStore) {
        return NULL;
    }

    permStore->permStore.userData = permStore;
    permStore->permStore.handler = MemoryPermissionStoreHandler;
    return permStore;
}

void DPS_DestroyMemoryPermissionStore(DPS_MemoryPermissionStore* permStore)
{
    size_t i;

    while (permStore->entries) {
        PermissionEntry* entry = permStore->entries;
        PermissionEntry* next = entry->next;
        while (entry->access) {
            Access* access = entry->access;
            Access* next = access->next;
            DPS_ClearKeyId(access->id);
            free(access);
            entry->access = next;
        }
        for (i = 0; i < entry->numTopics; ++i) {
            if (entry->topics[i]) {
                free(entry->topics[i]);
            }
        }
        if (entry->topics) {
            free(entry->topics);
        }
        free(entry);
        permStore->entries = next;
    }
    free(permStore);
}

static int MatchTopics(PermissionEntry* entry, const char** topics, size_t numTopics)
{
    size_t i;

    if (entry->numTopics != numTopics) {
        return DPS_FALSE;
    }
    for (i = 0; i < entry->numTopics; ++i) {
        if (strcmp(entry->topics[i], topics[i])) {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

DPS_Status DPS_SetPermission(DPS_MemoryPermissionStore* permStore, const char** topics, size_t numTopics,
                             const DPS_KeyId* keyId, DPS_Permission perms)
{
    PermissionEntry* newEntry = NULL;
    Access* newAccess = NULL;
    PermissionEntry** entry;
    Access** access = NULL;
    size_t i;

    for (entry = &permStore->entries; (*entry); entry = &(*entry)->next) {
        if (MatchTopics((*entry), topics, numTopics)) {
            break;
        }
    }
    if (*entry) {
        for (access = &(*entry)->access; (*access); access = &(*access)->next) {
            if ((!keyId && !(*access)->id) || DPS_SameKeyId(keyId, (*access)->id)) {
                break;
            }
        }
    }
    if (access && *access) {
        (*access)->perms = perms;
        return DPS_OK;
    }

    newAccess = calloc(1, sizeof(Access));
    if (!newAccess) {
        goto ErrorExit;
    }
    if (keyId) {
        newAccess->id = malloc(sizeof(DPS_KeyId));
        if (!newAccess->id) {
            goto ErrorExit;
        }
        DPS_CopyKeyId(newAccess->id, keyId);
    }
    newAccess->perms = perms;
    if (*entry) {
        (*access) = newAccess;
    } else {
        newEntry = calloc(1, sizeof(PermissionEntry));
        if (!newEntry) {
            goto ErrorExit;
        }
        if (numTopics) {
            newEntry->topics = calloc(numTopics, sizeof(char*));
            if (!newEntry->topics) {
                goto ErrorExit;
            }
            newEntry->numTopics = numTopics;
            for (i = 0; i < numTopics; ++i) {
                newEntry->topics[i] = strndup(topics[i], DPS_MAX_TOPIC_STRLEN);
                if (!newEntry->topics[i]) {
                    goto ErrorExit;
                }
            }
        }
        newEntry->access = newAccess;
        (*entry) = newEntry;
    }
    return DPS_OK;

 ErrorExit:
    if (newAccess) {
        DPS_ClearKeyId(newAccess->id);
        free(newAccess);
    }
    if (newEntry) {
        for (i = 0; i < newEntry->numTopics; ++i) {
            if (newEntry->topics[i]) {
                free(newEntry->topics[i]);
            }
        }
        if (newEntry->topics) {
            free(newEntry->topics);
        }
        free(newEntry);
    }
    return DPS_ERR_RESOURCES;
}

DPS_PermissionStore* DPS_MemoryPermissionStoreHandle(DPS_MemoryPermissionStore *permStore)
{
    DPS_DBGTRACE();

    if (!permStore) {
        return NULL;
    }
    return &permStore->permStore;
}
