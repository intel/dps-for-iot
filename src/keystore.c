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

#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>

#include <stdlib.h>
#include <string.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _DPS_MemoryKeyStoreEntry {
    DPS_UUID kid;
    uint8_t* key;
    size_t keyLen;
} DPS_MemoryKeyStoreEntry;

struct _DPS_MemoryKeyStore {
    DPS_KeyStore keyStore;

    DPS_MemoryKeyStoreEntry* entries;
    size_t entriesCount;
    size_t entriesCap;

    uint8_t* networkKey;
    size_t networkKeyLen;
};

static DPS_Status MemoryKeyStoreNetworkKeyCallback(DPS_KeyStore* keyStore, uint8_t* buffer, size_t bufferLen, size_t* keyLen)
{
    DPS_MemoryKeyStore* mks = keyStore->userData;
    if (!mks->networkKey) {
        return DPS_ERR_MISSING;
    }

    if (bufferLen < mks->networkKeyLen) {
        return DPS_ERR_RESOURCES;
    }

    memcpy(buffer, mks->networkKey, mks->networkKeyLen);
    *keyLen = mks->networkKeyLen;

    return DPS_OK;
}

static DPS_Status MemoryKeyStoreContentKeyCallback(DPS_KeyStore* keyStore, const DPS_UUID* kid, uint8_t* key, size_t keyLen)
{
    DPS_MemoryKeyStore* mks = keyStore->userData;
    size_t i;
    for (i = 0; i < mks->entriesCount; ++i) {
        DPS_MemoryKeyStoreEntry* entry = mks->entries + i;
        if (DPS_UUIDCompare(kid, &entry->kid) == 0) {
            if (keyLen < entry->keyLen) {
                DPS_ERRPRINT("Key has size %d, but callback given only %d buffer", entry->keyLen, keyLen);
                return DPS_ERR_MISSING;
            }
            memcpy(key, entry->key, entry->keyLen);
            return DPS_OK;
        }
    }
    return DPS_ERR_MISSING;
}

DPS_MemoryKeyStore* DPS_CreateMemoryKeyStore()
{
    DPS_MemoryKeyStore* mks = calloc(1, sizeof(DPS_MemoryKeyStore));
    mks->keyStore.userData = mks;
    mks->keyStore.contentKeyCB = MemoryKeyStoreContentKeyCallback;
    mks->keyStore.networkKeyCB = MemoryKeyStoreNetworkKeyCallback;
    return mks;
}

void DPS_DestroyMemoryKeyStore(DPS_MemoryKeyStore* mks)
{
    DPS_DBGPRINT("Destroying DPS_MemoryKeyStore %p\n", mks);
    if (!mks) {
        return;
    }
    for (size_t i = 0; i < mks->entriesCount; i++) {
        DPS_MemoryKeyStoreEntry* entry = mks->entries + i;
        free(entry->key);
    }
    free(mks->entries);
    free(mks->networkKey);
    free(mks);
}

DPS_Status DPS_SetNetworkKey(DPS_MemoryKeyStore* mks, uint8_t* key, size_t keyLen)
{
    if ((!key && keyLen > 0) || (key && keyLen == 0)) {
        return DPS_ERR_INVALID;
    }

    uint8_t* networkKey = NULL;
    if (key) {
        networkKey = calloc(1, keyLen);
        if (!networkKey) {
            return DPS_ERR_RESOURCES;
        }
        memcpy(networkKey, key, keyLen);
    }

    free(mks->networkKey);
    mks->networkKey = networkKey;
    mks->networkKeyLen = keyLen;
    return DPS_OK;
}

DPS_Status DPS_SetContentKey(DPS_MemoryKeyStore* mks, const DPS_UUID* kid, uint8_t* key, size_t keyLen)
{
    // Replace key if kid already exists.
    for (size_t i = 0; i < mks->entriesCount; i++) {
        DPS_MemoryKeyStoreEntry* entry = mks->entries + i;
        if (DPS_UUIDCompare(&entry->kid, kid) == 0) {
            uint8_t* newKey = NULL;
            if (key) {
                newKey = calloc(keyLen, sizeof(uint8_t));
                if (!newKey) {
                    return DPS_ERR_RESOURCES;
                }
                memcpy(newKey, key, keyLen);
            }
            free(entry->key);
            // TODO: if newKey == NULL, this is effectively a removal.
            entry->key = newKey;
            entry->keyLen = keyLen;
            return DPS_OK;
        }
    }

    // If kid doesn't exist, don't add a NULL key.
    if (!key) {
        return DPS_OK;
    }

    // Grow the entries array as needed.
    if (mks->entriesCount == mks->entriesCap) {
        size_t newCap = 1;
        if (mks->entriesCap) {
            newCap = mks->entriesCap * 2;
        }
        DPS_MemoryKeyStoreEntry *newEntries = realloc(mks->entries, newCap * sizeof(DPS_MemoryKeyStoreEntry));
        if (!newEntries) {
            return DPS_ERR_RESOURCES;
        }
        mks->entries = newEntries;
        mks->entriesCap = newCap;
    }

    // Add the new entry.
    DPS_MemoryKeyStoreEntry* entry = mks->entries + mks->entriesCount;
    uint8_t* newKey = calloc(keyLen, sizeof(uint8_t));
    if (!newKey) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(newKey, key, keyLen);
    entry->kid = *kid;
    entry->key = newKey;
    entry->keyLen = keyLen;
    mks->entriesCount++;
    return DPS_OK;
}

DPS_KeyStore* DPS_MemoryKeyStoreHandle(DPS_MemoryKeyStore *mks)
{
    if (!mks) {
        return NULL;
    }
    return &mks->keyStore;
}


/* TODO: Implement a FileKeyStore, that read the keys from a specified file. */
