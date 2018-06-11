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

#include <safe_lib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include "compat.h"
#include "crypto.h"
#include "node.h"

#include <stdlib.h>
#include <string.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_KeyStore* DPS_CreateKeyStore(DPS_KeyAndIdHandler keyAndIdHandler, DPS_KeyHandler keyHandler,
                                 DPS_EphemeralKeyHandler ephemeralKeyHandler, DPS_CAHandler caHandler)
{
    DPS_DBGTRACE();

    DPS_KeyStore* keyStore = calloc(1, sizeof(DPS_KeyStore));
    if (keyStore) {
        keyStore->keyAndIdHandler = keyAndIdHandler;
        keyStore->keyHandler = keyHandler;
        keyStore->ephemeralKeyHandler = ephemeralKeyHandler;
        keyStore->caHandler = caHandler;
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

DPS_Status DPS_SetKeyAndId(DPS_KeyStoreRequest* request, const DPS_Key* key, const DPS_KeyId* keyId)
{
    DPS_DBGTRACE();

    return request->setKeyAndId ? request->setKeyAndId(request, key, keyId) : DPS_ERR_MISSING;
}

DPS_Status DPS_SetKey(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    DPS_DBGTRACE();

    return request->setKey ? request->setKey(request, key) : DPS_ERR_MISSING;
}

DPS_Status DPS_SetCA(DPS_KeyStoreRequest* request, const char* ca)
{
    DPS_DBGTRACE();

    return request->setCA ? request->setCA(request, ca): DPS_ERR_MISSING;
}

typedef struct _MemoryKeyStoreEntry {
    DPS_KeyId keyId;
    DPS_Key key;
} MemoryKeyStoreEntry;

struct _DPS_MemoryKeyStore {
    DPS_KeyStore keyStore;
    DPS_RBG* rbg;

    MemoryKeyStoreEntry* entries;
    size_t entriesCount;
    size_t entriesCap;

    DPS_KeyId networkId;
    DPS_Key networkKey;

    char *ca;
};

static int SameKeyId(const DPS_KeyId* a, const DPS_KeyId* b)
{
    return a && b && (a->len == b->len) && (memcmp(a->id, b->id, b->len) == 0);
}

static MemoryKeyStoreEntry* MemoryKeyStoreLookup(DPS_MemoryKeyStore* mks, const DPS_KeyId* keyId)
{
    MemoryKeyStoreEntry* entry;
    size_t i;

    for (i = 0; i < mks->entriesCount; ++i) {
        entry = mks->entries + i;
        if (SameKeyId(&entry->keyId, keyId)) {
            return entry;
        }
    }
    return NULL;
}

static DPS_Status MemoryKeyStoreGrow(DPS_MemoryKeyStore* mks)
{
    if (mks->entriesCount == mks->entriesCap) {
        size_t newCap = 1;
        if (mks->entriesCap) {
            newCap = mks->entriesCap * 2;
        }
        MemoryKeyStoreEntry *newEntries = realloc(mks->entries, newCap * sizeof(MemoryKeyStoreEntry));
        if (!newEntries) {
            return DPS_ERR_RESOURCES;
        }
        memset(newEntries + mks->entriesCap, 0, (newCap - mks->entriesCap) * sizeof(MemoryKeyStoreEntry));
        mks->entries = newEntries;
        mks->entriesCap = newCap;
    }
    return DPS_OK;
}

static DPS_Status MemoryKeyStoreSetKey(MemoryKeyStoreEntry* entry, const DPS_Key* key)
{
    uint8_t* newKey = NULL;
    size_t newLen = 0;
    if (entry->key.type != DPS_KEY_SYMMETRIC) {
        return DPS_ERR_ARGS;
    }
    if (key) {
        if (key->type != DPS_KEY_SYMMETRIC) {
            return DPS_ERR_ARGS;
        }
        newKey = malloc(key->symmetric.len);
        if (!newKey) {
            return DPS_ERR_RESOURCES;
        }
        newLen = key->symmetric.len;
        memcpy_s(newKey, newLen, key->symmetric.key, key->symmetric.len);
    }
    entry->key.type = DPS_KEY_SYMMETRIC;
    if (entry->key.symmetric.key) {
        free((uint8_t*)entry->key.symmetric.key);
    }
    entry->key.symmetric.key = newKey;
    entry->key.symmetric.len = newLen;
    return DPS_OK;
}

static DPS_Status MemoryKeyStoreSetCertificate(MemoryKeyStoreEntry* entry, const char* cert,
                                               const char* key, const char* password)
{
    char *newCert = NULL;
    char *newKey = NULL;
    char *newPassword = NULL;

    newCert = strndup(cert, RSIZE_MAX_STR);
    if (!newCert) {
        goto ErrorExit;
    }
    if (key) {
        newKey = strndup(key, RSIZE_MAX_STR);
        if (!newKey) {
            goto ErrorExit;
        }
    }
    if (password) {
        newPassword = strndup(password, RSIZE_MAX_STR);
        if (!newPassword) {
            goto ErrorExit;
        }
    }
    entry->key.type = DPS_KEY_EC_CERT;
    if (entry->key.cert.cert) {
        free((char*)entry->key.cert.cert);
    }
    entry->key.cert.cert = newCert;
    if (entry->key.cert.privateKey) {
        free((char*)entry->key.cert.privateKey);
    }
    entry->key.cert.privateKey = newKey;
    if (entry->key.cert.password) {
        free((char*)entry->key.cert.password);
    }
    entry->key.cert.password = newPassword;
    return DPS_OK;

ErrorExit:
    if (newPassword) {
        free(newPassword);
    }
    if (newKey) {
        free(newKey);
    }
    if (newCert) {
        free(newCert);
    }
    return DPS_ERR_RESOURCES;
}

static DPS_Status MemoryKeyStoreKeyAndIdHandler(DPS_KeyStoreRequest* request)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);

    if (!mks->networkId.id || !mks->networkKey.symmetric.key) {
        return DPS_ERR_MISSING;
    }
    return DPS_SetKeyAndId(request, &mks->networkKey, &mks->networkId);
}

static DPS_Status MemoryKeyStoreKeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    MemoryKeyStoreEntry* entry;

    entry = MemoryKeyStoreLookup(mks, keyId);
    if (entry) {
        return DPS_SetKey(request, &entry->key);
    }

    if (SameKeyId(&mks->networkId, keyId)) {
        return DPS_SetKey(request, &mks->networkKey);
    }

    return DPS_ERR_MISSING;
}

static DPS_Status MemoryKeyStoreEphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    DPS_Key k;
    DPS_Status ret;

    switch (key->type) {
    case DPS_KEY_SYMMETRIC: {
        uint8_t key[AES_256_KEY_LEN];
        ret = DPS_RandomKey(mks->rbg, key);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_SYMMETRIC;
        k.symmetric.key = key;
        k.symmetric.len = AES_256_KEY_LEN;
        return DPS_SetKey(request, &k);
    }
    case DPS_KEY_EC: {
        uint8_t x[EC_MAX_COORD_LEN];
        uint8_t y[EC_MAX_COORD_LEN];
        uint8_t d[EC_MAX_COORD_LEN];
        ret = DPS_EphemeralKey(mks->rbg, key->ec.curve, x, y, d);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_EC;
        k.ec.curve = key->ec.curve;
        k.ec.x = x;
        k.ec.y = y;
        k.ec.d = d;
        return DPS_SetKey(request, &k);
    }
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
}

static DPS_Status MemoryKeyStoreCAHandler(DPS_KeyStoreRequest* request)
{
    DPS_MemoryKeyStore* mks = (DPS_MemoryKeyStore*)DPS_KeyStoreHandle(request);
    return DPS_SetCA(request, mks->ca);
}

DPS_MemoryKeyStore* DPS_CreateMemoryKeyStore()
{
    DPS_MemoryKeyStore* mks;
    DPS_RBG* rbg;

    DPS_DBGTRACE();

    mks = calloc(1, sizeof(DPS_MemoryKeyStore));
    if (!mks) {
        return NULL;
    }
    rbg = DPS_CreateRBG();
    if (!rbg) {
        free(mks);
        return NULL;
    }

    mks->rbg = rbg;
    mks->keyStore.userData = mks;
    mks->keyStore.keyAndIdHandler = MemoryKeyStoreKeyAndIdHandler;
    mks->keyStore.keyHandler = MemoryKeyStoreKeyHandler;
    mks->keyStore.ephemeralKeyHandler = MemoryKeyStoreEphemeralKeyHandler;
    mks->keyStore.caHandler = MemoryKeyStoreCAHandler;
    return mks;
}

void DPS_DestroyMemoryKeyStore(DPS_MemoryKeyStore* mks)
{
    DPS_DBGTRACE();

    if (!mks) {
        return;
    }
    if (mks->rbg) {
        DPS_DestroyRBG(mks->rbg);
    }
    for (size_t i = 0; i < mks->entriesCount; i++) {
        MemoryKeyStoreEntry* entry = mks->entries + i;
        DPS_ClearKeyId(&entry->keyId);
        if (entry->key.type == DPS_KEY_SYMMETRIC) {
            free((uint8_t*)entry->key.symmetric.key);
        } else if (entry->key.type == DPS_KEY_EC_CERT) {
            free((char*)entry->key.cert.cert);
            if (entry->key.cert.privateKey) {
                free((char*)entry->key.cert.privateKey);
            }
            if (entry->key.cert.password) {
                free((char*)entry->key.cert.password);
            }
        }
    }
    if (mks->entries) {
        free(mks->entries);
    }
    DPS_ClearKeyId(&mks->networkId);
    if (mks->networkKey.symmetric.key) {
        free((uint8_t*)mks->networkKey.symmetric.key);
    }
    if (mks->ca) {
        free(mks->ca);
    }
    free(mks);
}

DPS_Status DPS_SetNetworkKey(DPS_MemoryKeyStore* mks, const DPS_KeyId* keyId, const DPS_Key* key)
{
    DPS_KeyId id;

    DPS_DBGTRACE();

    if (!keyId || (keyId->len == 0) || (key && (key->type != DPS_KEY_SYMMETRIC))) {
        return DPS_ERR_INVALID;
    }

    if (!DPS_CopyKeyId(&id, keyId)) {
        return DPS_ERR_RESOURCES;
    }

    uint8_t* k = NULL;
    size_t len = 0;
    if (key) {
        k = malloc(key->symmetric.len);
        if (!k) {
            DPS_ClearKeyId(&id);
            return DPS_ERR_RESOURCES;
        }
        len = key->symmetric.len;
        memcpy_s(k, len, key->symmetric.key, key->symmetric.len);
    }

    DPS_ClearKeyId(&mks->networkId);
    mks->networkId = id;
    if (mks->networkKey.symmetric.key) {
        free((uint8_t*)mks->networkKey.symmetric.key);
    }
    mks->networkKey.symmetric.key = k;
    mks->networkKey.symmetric.len = len;

    return DPS_OK;
}

DPS_Status DPS_SetContentKey(DPS_MemoryKeyStore* mks, const DPS_KeyId* keyId, const DPS_Key* key)
{
    MemoryKeyStoreEntry* entry;

    DPS_DBGTRACE();

    /* Replace key if key ID already exists. */
    entry = MemoryKeyStoreLookup(mks, keyId);
    if (entry) {
        if (MemoryKeyStoreSetKey(entry, key) != DPS_OK) {
            return DPS_ERR_RESOURCES;
        }
        return DPS_OK;
    }

    /* If key ID doesn't exist, don't add a NULL key. */
    if (!key) {
        return DPS_OK;
    }

    /* Grow the entries array as needed. */
    if (MemoryKeyStoreGrow(mks) != DPS_OK) {
        return DPS_ERR_RESOURCES;
    }

    /* Add the new entry. */
    entry = mks->entries + mks->entriesCount;
    DPS_KeyId id;
    if (!DPS_CopyKeyId(&id, keyId)) {
        return DPS_ERR_RESOURCES;
    }
    if (MemoryKeyStoreSetKey(entry, key) != DPS_OK) {
        DPS_ClearKeyId(&id);
        return DPS_ERR_RESOURCES;
    }
    entry->keyId = id;
    mks->entriesCount++;
    return DPS_OK;
}

DPS_Status DPS_SetTrustedCA(DPS_MemoryKeyStore* mks, const char* ca)
{
    DPS_DBGTRACE();

    char *newCA = strndup(ca, RSIZE_MAX_STR);
    if (!newCA) {
        return DPS_ERR_RESOURCES;
    }
    if (mks->ca) {
        free(mks->ca);
    }
    mks->ca = newCA;
    return DPS_OK;
}

DPS_Status DPS_SetCertificate(DPS_MemoryKeyStore* mks, const char* cert, const char* key,
                              const char* password)
{
    char* cn = NULL;
    DPS_KeyId keyId;
    MemoryKeyStoreEntry* entry;

    DPS_DBGTRACE();

    if (!cert) {
        return DPS_ERR_ARGS;
    }

    cn = DPS_CertificateCN(cert);
    if (!cn) {
        goto ErrorExit;
    }
    keyId.id = (const uint8_t*)cn;
    keyId.len = strnlen_s(cn, RSIZE_MAX_STR);
    if (keyId.len == RSIZE_MAX_STR) {
        goto ErrorExit;
    }

    /* Replace cert if id already exists. */
    entry = MemoryKeyStoreLookup(mks, &keyId);
    if (entry) {
        if (MemoryKeyStoreSetCertificate(entry, cert, key, password) != DPS_OK) {
            goto ErrorExit;
        }
        return DPS_OK;
    }

    /* Grow the certificates array as needed. */
    if (MemoryKeyStoreGrow(mks) != DPS_OK) {
        goto ErrorExit;
    }

    /* Add the new entry. */
    entry = mks->entries + mks->entriesCount;
    if (MemoryKeyStoreSetCertificate(entry, cert, key, password) != DPS_OK) {
        goto ErrorExit;
    }
    entry->keyId = keyId;
    mks->entriesCount++;
    return DPS_OK;

ErrorExit:
    if (cn) {
        free(cn);
    }
    return DPS_ERR_RESOURCES;
}

DPS_KeyStore* DPS_MemoryKeyStoreHandle(DPS_MemoryKeyStore *mks)
{
    if (!mks) {
        return NULL;
    }
    return &mks->keyStore;
}

/* TODO: Implement a FileKeyStore, that read the keys from a specified file. */
