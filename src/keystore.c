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

DPS_KeyStore* DPS_CreateKeyStore(DPS_KeyAndIdentityHandler keyAndIdentityHandler, DPS_KeyHandler keyHandler,
                                 DPS_CAHandler caHandler, DPS_CertHandler certHandler)
{
    DPS_DBGTRACE();

    DPS_KeyStore* keyStore = calloc(1, sizeof(DPS_KeyStore));
    if (keyStore) {
        keyStore->keyAndIdentityHandler = keyAndIdentityHandler;
        keyStore->keyHandler = keyHandler;
        keyStore->caHandler = caHandler;
        keyStore->certHandler = certHandler;
    }
    return keyStore;
}

void DPS_DestroyKeyStore(DPS_KeyStore* keyStore)
{
    DPS_DBGTRACE();

    if (!keyStore) {
        return;
    }
    free(keyStore);
}

DPS_Status DPS_SetKeyStoreData(DPS_KeyStore* keyStore, void* data)
{
    if (keyStore) {
        keyStore->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetKeyStoreData(const DPS_KeyStore* keyStore)
{
    return keyStore ? keyStore->userData : NULL;
}

DPS_KeyStore* DPS_KeyStoreHandle(DPS_KeyStoreRequest* request)
{
    return request ? request->keyStore : NULL;
}

DPS_Status DPS_SetKeyAndIdentity(DPS_KeyStoreRequest* request, const DPS_Key* key, const unsigned char* id, size_t idLen)
{
    return request->setKeyAndIdentity ? request->setKeyAndIdentity(request, key, id, idLen) : DPS_ERR_MISSING;
}

DPS_Status DPS_SetKey(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    return request->setKey ? request->setKey(request, key) : DPS_ERR_MISSING;
}

DPS_Status DPS_SetCA(DPS_KeyStoreRequest* request, const unsigned char* ca, size_t len)
{
    return request->setCA ? request->setCA(request, ca, len): DPS_ERR_MISSING;
}

DPS_Status DPS_SetCert(DPS_KeyStoreRequest* request, const unsigned char* cert, size_t certLen, const DPS_Key* key, const unsigned char* password, size_t passwordLen)
{
    return request->setCert ? request->setCert(request, cert, certLen, key, password, passwordLen) : DPS_ERR_MISSING;
}

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

    uint8_t* networkId;
    size_t networkIdLen;
    uint8_t* networkKey;
    size_t networkKeyLen;

    unsigned char *ca;
    size_t caLen;

    unsigned char *cert;
    size_t certLen;
    unsigned char *privateKey;
    size_t privateKeyLen;
    unsigned char *password;
    size_t passwordLen;
};

static DPS_Status MemoryKeyStoreKeyAndIdentityHandler(DPS_KeyStoreRequest* request)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    DPS_Key k;
    if (!mks->networkId || !mks->networkKey) {
        return DPS_ERR_MISSING;
    }
    k.type = DPS_KEY_SYMMETRIC;
    k.symmetric.key = mks->networkKey;
    k.symmetric.len = mks->networkKeyLen;
    return DPS_SetKeyAndIdentity(request, &k, mks->networkId, mks->networkIdLen);
}

static DPS_Status MemoryKeyStoreKeyHandler(DPS_KeyStoreRequest* request, const unsigned char* id, size_t len)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    DPS_Key k;
    size_t i;

    if (len == sizeof(DPS_UUID)) {
        for (i = 0; i < mks->entriesCount; ++i) {
            DPS_MemoryKeyStoreEntry* entry = mks->entries + i;
            if (DPS_UUIDCompare((const DPS_UUID*)id, &entry->kid) == 0) {
                k.type = DPS_KEY_SYMMETRIC;
                k.symmetric.key = entry->key;
                k.symmetric.len = entry->keyLen;
                return DPS_SetKey(request, &k);
            }
        }
    }

    if (len == mks->networkIdLen) {
        if (memcmp(id, mks->networkId, mks->networkIdLen) == 0) {
            k.type = DPS_KEY_SYMMETRIC;
            k.symmetric.key = mks->networkKey;
            k.symmetric.len = mks->networkKeyLen;
            return DPS_SetKey(request, &k);
        }
    }

    return DPS_ERR_MISSING;
}

static DPS_Status MemoryKeyStoreCAHandler(DPS_KeyStoreRequest* request)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    return DPS_SetCA(request, mks->ca, mks->caLen);
}

static DPS_Status MemoryKeyStoreCertHandler(DPS_KeyStoreRequest* request)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    DPS_Key k;
    k.type = DPS_KEY_SYMMETRIC;
    k.symmetric.key = mks->privateKey;
    k.symmetric.len = mks->privateKeyLen;
    return DPS_SetCert(request, mks->cert, mks->certLen, &k, mks->password, mks->passwordLen);
}

DPS_MemoryKeyStore* DPS_CreateMemoryKeyStore()
{
    DPS_DBGTRACE();

    DPS_MemoryKeyStore* mks = calloc(1, sizeof(DPS_MemoryKeyStore));
    if (mks) {
        mks->keyStore.userData = mks;
        mks->keyStore.keyAndIdentityHandler = MemoryKeyStoreKeyAndIdentityHandler;
        mks->keyStore.keyHandler = MemoryKeyStoreKeyHandler;
        mks->keyStore.caHandler = MemoryKeyStoreCAHandler;
        mks->keyStore.certHandler = MemoryKeyStoreCertHandler;
    }
    return mks;
}

void DPS_DestroyMemoryKeyStore(DPS_MemoryKeyStore* mks)
{
    DPS_DBGTRACE();

    if (!mks) {
        return;
    }
    for (size_t i = 0; i < mks->entriesCount; i++) {
        DPS_MemoryKeyStoreEntry* entry = mks->entries + i;
        free(entry->key);
    }
    if (mks->entries) {
        free(mks->entries);
    }
    if (mks->networkId) {
        free(mks->networkId);
    }
    if (mks->networkKey) {
        free(mks->networkKey);
    }
    if (mks->ca) {
        free(mks->ca);
    }
    if (mks->cert) {
        free(mks->cert);
    }
    if (mks->privateKey) {
        free(mks->privateKey);
    }
    if (mks->password) {
        free(mks->password);
    }
    free(mks);
}

DPS_Status DPS_SetNetworkKey(DPS_MemoryKeyStore* mks, const uint8_t* id, size_t idLen, const uint8_t* key, size_t keyLen)
{
    DPS_DBGTRACE();

    if (!id || (idLen == 0) || (!key && keyLen > 0) || (key && keyLen == 0)) {
        return DPS_ERR_INVALID;
    }

    uint8_t* networkId = networkId = calloc(1, idLen);
    if (!networkId) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(networkId, id, idLen);

    uint8_t* networkKey = NULL;
    if (key) {
        networkKey = calloc(1, keyLen);
        if (!networkKey) {
            free(mks->networkId);
            return DPS_ERR_RESOURCES;
        }
        memcpy(networkKey, key, keyLen);
    }

    if (mks->networkId) {
        free(mks->networkId);
    }
    mks->networkId = networkId;
    mks->networkIdLen = idLen;
    if (mks->networkKey) {
        free(mks->networkKey);
    }
    mks->networkKey = networkKey;
    mks->networkKeyLen = keyLen;

    return DPS_OK;
}

DPS_Status DPS_SetContentKey(DPS_MemoryKeyStore* mks, const DPS_UUID* kid, const uint8_t* key, size_t keyLen)
{
    DPS_DBGTRACE();

    /* Replace key if kid already exists. */
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
            if (entry->key) {
                free(entry->key);
            }
            entry->key = newKey;
            entry->keyLen = keyLen;
            return DPS_OK;
        }
    }

    /* If kid doesn't exist, don't add a NULL key. */
    if (!key) {
        return DPS_OK;
    }

    /* Grow the entries array as needed. */
    if (mks->entriesCount == mks->entriesCap) {
        size_t newCap = 1;
        if (mks->entriesCap) {
            newCap = mks->entriesCap * 2;
        }
        DPS_MemoryKeyStoreEntry *newEntries = realloc(mks->entries, newCap * sizeof(DPS_MemoryKeyStoreEntry));
        if (!newEntries) {
            return DPS_ERR_RESOURCES;
        }
        memset(newEntries + mks->entriesCap, 0, (newCap - mks->entriesCap) * sizeof(DPS_MemoryKeyStoreEntry));
        mks->entries = newEntries;
        mks->entriesCap = newCap;
    }

    /* Add the new entry. */
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

DPS_Status DPS_SetTrustedCA(DPS_MemoryKeyStore* mks, const char* ca, size_t len)
{
    DPS_DBGTRACE();

    unsigned char *newCA = malloc(len);
    if (!newCA) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(newCA, ca, len);
    if (mks->ca) {
        free(mks->ca);
    }
    mks->ca = newCA;
    mks->caLen = len;
    return DPS_OK;
}

DPS_Status DPS_SetCertificate(DPS_MemoryKeyStore* mks, const char* cert, size_t certLen,
                              const char* key, size_t keyLen,
                              const char* password, size_t passwordLen)
{
    DPS_DBGTRACE();

    unsigned char *newCert = malloc(certLen);
    if (!newCert) {
        return DPS_ERR_RESOURCES;
    }
    memcpy(newCert, cert, certLen);

    unsigned char *newKey = malloc(keyLen);
    if (!newKey) {
        free(newCert);
        return DPS_ERR_RESOURCES;
    }
    memcpy(newKey, key, keyLen);

    unsigned char *newPassword = malloc(passwordLen);
    if (!newPassword) {
        free(newKey);
        free(newCert);
        return DPS_ERR_RESOURCES;
    }
    memcpy(newPassword, password, passwordLen);

    if (mks->cert) {
        free(mks->cert);
    }
    mks->cert = newCert;
    mks->certLen = certLen;
    if (mks->privateKey) {
        free(mks->privateKey);
    }
    mks->privateKey = newKey;
    mks->privateKeyLen = keyLen;
    if (mks->password) {
        free(mks->password);
    }
    mks->password = newPassword;
    mks->passwordLen = passwordLen;

    return DPS_OK;
}

DPS_KeyStore* DPS_MemoryKeyStoreHandle(DPS_MemoryKeyStore *mks)
{
    DPS_DBGTRACE();

    if (!mks) {
        return NULL;
    }
    return &mks->keyStore;
}

/* TODO: Implement a FileKeyStore, that read the keys from a specified file. */
