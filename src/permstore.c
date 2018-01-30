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

#include <stdlib.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static const DPS_UUID _WildcardId = {
    .val = { 0x67, 0xa2, 0x46, 0x46, 0xd8, 0x7b, 0x4d, 0x7c, 0x9e, 0x7b, 0x12, 0xbb, 0x8d, 0x50, 0x13, 0x42 }
};
static const DPS_KeyId WildcardId = { _WildcardId.val, sizeof(_WildcardId.val) };
const DPS_KeyId* const DPS_WILDCARD_ID = &WildcardId;

DPS_PermissionStore* DPS_CreatePermissionStore(DPS_GetPermissionsHandler getHandler)
{
    DPS_DBGTRACE();

    DPS_PermissionStore* permStore = calloc(1, sizeof(DPS_PermissionStore));
    if (permStore) {
        permStore->getHandler = getHandler;
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

typedef struct _DPS_Permission {
    DPS_KeyId keyId;
    DPS_Permissions bits;
    struct _DPS_Permission* next;
} DPS_Permission;

struct _DPS_MemoryPermissionStore {
    DPS_PermissionStore permStore;
    DPS_Permission* permissions;
};

static DPS_Permissions MemoryPermissionStoreGetHandler(const DPS_PermissionStore* ps,
                                                       const DPS_KeyId* keyId)
{
    DPS_MemoryPermissionStore* permStore = (DPS_MemoryPermissionStore*)ps->userData;
    const DPS_Permission* permission;

    DPS_DBGTRACEA("permStore=%p,keyId={id=%p,len=%d}\n", permStore, keyId ? keyId->id : NULL,
                  keyId ? keyId->len : 0);

    for (permission = permStore->permissions; permission; permission = permission->next) {
        if (DPS_SameKeyId(&permission->keyId, keyId) ||
            DPS_SameKeyId(&permission->keyId, DPS_WILDCARD_ID)) {
            return permission->bits;
        }
    }
    return 0;
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
    permStore->permStore.getHandler = MemoryPermissionStoreGetHandler;
    return permStore;
}

void DPS_DestroyMemoryPermissionStore(DPS_MemoryPermissionStore* permStore)
{
    while (permStore->permissions) {
        DPS_Permission* next = permStore->permissions->next;
        DPS_ClearKeyId(&permStore->permissions->keyId);
        free(permStore->permissions);
        permStore->permissions = next;
    }
}

DPS_Status DPS_SetPermissions(DPS_MemoryPermissionStore* permStore, const DPS_KeyId* keyId,
                              DPS_Permissions bits)
{
    DPS_Permission** permission;

    DPS_DBGTRACEA("permStore=%p,keyId={id=%p,len=%d},bits=0x%x\n",
                  permStore, keyId ? keyId->id : NULL, keyId ? keyId->len : 0, bits);

    for (permission = &permStore->permissions; (*permission); permission = &(*permission)->next) {
        if (DPS_SameKeyId(&(*permission)->keyId, keyId)) {
            (*permission)->bits = bits;
            return DPS_OK;
        }
    }
    (*permission) = malloc(sizeof(DPS_Permission));
    if (!(*permission)) {
        return DPS_ERR_RESOURCES;
    }
    if (!DPS_CopyKeyId(&(*permission)->keyId, keyId)) {
        free (*permission);
        (*permission) = NULL;
        return DPS_ERR_RESOURCES;
    }
    (*permission)->bits = bits;
    (*permission)->next = NULL;
    return DPS_OK;
}

DPS_PermissionStore* DPS_MemoryPermissionStoreHandle(DPS_MemoryPermissionStore *permStore)
{
    DPS_DBGTRACE();

    if (!permStore) {
        return NULL;
    }
    return &permStore->permStore;
}
