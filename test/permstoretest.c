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

#include "test.h"
#include <dps/dps.h>

static int PermissionHandler(DPS_PermissionStoreRequest* request)
{
    return DPS_FALSE;
}

static int PublicationAuthorized(const DPS_PermissionStore* permStore,
                                 const DPS_KeyId* publisher, const DPS_Publication* pub)
{
    return DPS_FALSE;
}

int main(int argc, char** argv)
{
    DPS_PermissionStore* permStore;
    DPS_Status ret;
    void* userData;

    /* Create and destroy */
    permStore = DPS_CreatePermissionStore(PermissionHandler);
    ASSERT(permStore);
    DPS_DestroyPermissionStore(permStore);
    permStore = NULL;

    /* Destroy NULL key store */
    DPS_DestroyPermissionStore(permStore);
    permStore = NULL;

    /* Set and get user data */
    permStore = DPS_CreatePermissionStore(PermissionHandler);
    ASSERT(permStore);
    ret = DPS_SetPermissionStoreData(permStore, (void*)1);
    ASSERT(ret == DPS_OK);
    userData = DPS_GetPermissionStoreData(permStore);
    ASSERT(userData == (void*)1);
    DPS_DestroyPermissionStore(permStore);
    permStore = NULL;

    /* Set user data on NULL key store */
    ret = DPS_SetPermissionStoreData(permStore, (void*)1);
    ASSERT(ret != DPS_OK);

    return EXIT_SUCCESS;
}
