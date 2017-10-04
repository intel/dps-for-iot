/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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

static DPS_Status ContentKeyHandler(DPS_KeyStore* keyStore, const DPS_UUID* kid, uint8_t* key, size_t keyLen)
{
    return DPS_ERR_MISSING;
}

static  DPS_Status NetworkKeyHandler(DPS_KeyStore* keyStore, uint8_t* buffer, size_t bufferLen, size_t* keyLen)
{
    return DPS_ERR_MISSING;
}

int main(int argc, char** argv)
{
    DPS_KeyStore* keyStore;
    DPS_Status ret;
    void* userData;

    /* Create and destroy */
    keyStore = DPS_CreateKeyStore(ContentKeyHandler, NetworkKeyHandler);
    ASSERT(keyStore);
    DPS_DestroyKeyStore(keyStore);
    keyStore = NULL;

    /* Destroy NULL key store */
    DPS_DestroyKeyStore(keyStore);
    keyStore = NULL;

    /* Set and get user data */
    keyStore = DPS_CreateKeyStore(ContentKeyHandler, NetworkKeyHandler);
    ASSERT(keyStore);
    ret = DPS_SetKeyStoreData(keyStore, (void*)1);
    ASSERT(ret == DPS_OK);
    userData = DPS_GetKeyStoreData(keyStore);
    ASSERT(userData == (void*)1);
    DPS_DestroyKeyStore(keyStore);
    keyStore = NULL;

    /* Set user data on NULL key store */
    ret = DPS_SetKeyStoreData(keyStore, (void*)1);
    ASSERT(ret != DPS_OK);

    return EXIT_SUCCESS;

Failed:
    return EXIT_FAILURE;
}
