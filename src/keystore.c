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
#include <dps/keystore.h>
#include <dps/private/crypto.h>
#include <dps/private/node.h>

#include <stdlib.h>
#include <string.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _KeyStoreEntry {
    DPS_KeyId keyId;
    DPS_Key key;
} KeyStoreEntry;

/*
 * This naive reference implementation stores keys in memory
 */
typedef struct _ReferenceKeyStore {
    DPS_KeyStore refKS;
    DPS_RBG* rbg;

    KeyStoreEntry* entries;
    size_t entriesCount;
    size_t entriesCap;

    DPS_KeyId networkId;
    DPS_Key networkKey;

    char *ca;

} ReferenceKeyStore;

static int SameKeyId(const DPS_KeyId* a, const DPS_KeyId* b)
{
    return a && b && (a->len == b->len) && (memcmp(a->id, b->id, b->len) == 0);
}

DPS_KeyId* DPS_CopyKeyId(DPS_KeyId* dest, const DPS_KeyId* src)
{
    dest->len = src->len;
    memcpy((uint8_t*)dest->id, src->id, src->len);
    return dest;
}

void DPS_ClearKeyId(DPS_KeyId* keyId)
{
    memset(keyId, 0, sizeof(DPS_KeyId));
}

static KeyStoreEntry* KeyStoreLookup(ReferenceKeyStore* refKS, const DPS_KeyId* keyId)
{
    KeyStoreEntry* entry;
    size_t i;

    for (i = 0; i < refKS->entriesCount; ++i) {
        entry = refKS->entries + i;
        if (SameKeyId(&entry->keyId, keyId)) {
            return entry;
        }
    }
    return NULL;
}

static DPS_Status KeyStoreGrow(ReferenceKeyStore* refKS)
{
    if (refKS->entriesCount == refKS->entriesCap) {
        size_t newCap = 1;
        if (refKS->entriesCap) {
            newCap = refKS->entriesCap * 2;
        }
        KeyStoreEntry *newEntries = realloc(refKS->entries, newCap * sizeof(KeyStoreEntry));
        if (!newEntries) {
            return DPS_ERR_RESOURCES;
        }
        memset(newEntries + refKS->entriesCap, 0, (newCap - refKS->entriesCap) * sizeof(KeyStoreEntry));
        refKS->entries = newEntries;
        refKS->entriesCap = newCap;
    }
    return DPS_OK;
}

static DPS_Status KeyStoreSetKey(KeyStoreEntry* entry, const DPS_Key* key)
{
    if (entry->key.type != DPS_KEY_SYMMETRIC) {
        return DPS_ERR_ARGS;
    }
    entry->key.type = DPS_KEY_SYMMETRIC;
    memcpy(entry->key.symmetric.key, key->symmetric.key, key->symmetric.len);
    entry->key.symmetric.len =  key->symmetric.len;
    return DPS_OK;
}

#define MAX_CERT_LEN 1024
#define MAX_KEY_LEN   512
#define MAX_PWD_LEN   512

static DPS_Status SetCertificate(KeyStoreEntry* entry,
                                 const char* cert,
                                 const char* key,
                                 const char* password)
{
    char *newCert = NULL;
    char *newKey = NULL;
    char *newPassword = NULL;

    newCert = strndup(cert, MAX_CERT_LEN);
    if (!newCert) {
        goto ErrorExit;
    }
    if (key) {
        newKey = strndup(key, MAX_KEY_LEN);
        if (!newKey) {
            goto ErrorExit;
        }
    }
    if (password) {
        newPassword = strndup(password, MAX_PWD_LEN);
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

static DPS_Status KeyAndIdReq(DPS_KeyStore* keyStore, DPS_KeyResponse response, void* data)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;

    if (!refKS->networkId.id || !refKS->networkKey.symmetric.key) {
        return DPS_ERR_MISSING;
    }
    return response(&refKS->networkKey, &refKS->networkId, data);
}

static DPS_Status KeyReq(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, DPS_KeyResponse response, void* data)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    KeyStoreEntry* entry;

    entry = KeyStoreLookup(refKS, keyId);
    if (entry) {
        return response(&entry->key, keyId, data);
    }
    if (SameKeyId(&refKS->networkId, keyId)) {
        return response(&refKS->networkKey, keyId, data);
    }

    return DPS_ERR_MISSING;
}

static DPS_Status EphemeralKeyReq(DPS_KeyStore* keyStore, const DPS_Key* key, DPS_KeyResponse response, void* data)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    DPS_Key k;
    DPS_Status ret;

    switch (key->type) {
    case DPS_KEY_SYMMETRIC: {
        ret = DPS_RandomKey(refKS->rbg, k.symmetric.key);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_SYMMETRIC;
        k.symmetric.len = AES_256_KEY_LEN;
        return response(&k, NULL, data);
    }
    case DPS_KEY_EC: {
        ret = DPS_EphemeralKey(refKS->rbg, key->ec.curve, k.ec.x, k.ec.y, k.ec.d);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_EC;
        k.ec.curve = key->ec.curve;
        return response(&k, NULL, data);
    }
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
}

static DPS_Status CAChainReq(DPS_KeyStore* keyStore, DPS_CAChainResponse response, void* data)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    return response(refKS->ca, data);
}

DPS_KeyStore* DPS_CreateKeyStore()
{
    ReferenceKeyStore* refKS;

    DPS_DBGTRACE();

    refKS = calloc(1, sizeof(ReferenceKeyStore));
    if (!refKS) {
        return NULL;
    }
    refKS->rbg = DPS_CreateRBG();
    if (!refKS->rbg) {
        free(refKS);
        return NULL;
    }
    refKS->refKS.keyAndIdRequest = KeyAndIdReq;
    refKS->refKS.keyRequest = KeyReq;
    refKS->refKS.ephemeralKeyRequest = EphemeralKeyReq;
    refKS->refKS.caChainRequest = CAChainReq;

    return (DPS_KeyStore*)refKS;
}

void DPS_DestroyKeyStore(DPS_KeyStore* keyStore)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    size_t i;
    DPS_DBGTRACE();

    if (!refKS) {
        return;
    }
    if (refKS->rbg) {
        DPS_DestroyRBG(refKS->rbg);
    }
    for (i = 0; i < refKS->entriesCount; i++) {
        KeyStoreEntry* entry = refKS->entries + i;
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
    if (refKS->entries) {
        free(refKS->entries);
    }
    DPS_ClearKeyId(&refKS->networkId);
    if (refKS->networkKey.symmetric.key) {
        free((uint8_t*)refKS->networkKey.symmetric.key);
    }
    if (refKS->ca) {
        free(refKS->ca);
    }
    free(refKS);
}

DPS_Status DPS_SetNetworkKey(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    DPS_DBGTRACE();

    if (!keyId || (keyId->len == 0) || (key && (key->type != DPS_KEY_SYMMETRIC))) {
        return DPS_ERR_INVALID;
    }

    DPS_CopyKeyId(&refKS->networkId, keyId);
    memcpy(refKS->networkKey.symmetric.key, key->symmetric.key, key->symmetric.len);
    refKS->networkKey.symmetric.len = key->symmetric.len;

    return DPS_OK;
}

DPS_Status DPS_SetContentKey(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    KeyStoreEntry* entry;

    DPS_DBGTRACE();

    /* Replace key if key ID already exists. */
    entry = KeyStoreLookup(refKS, keyId);
    if (entry) {
        if (KeyStoreSetKey(entry, key) != DPS_OK) {
            return DPS_ERR_RESOURCES;
        }
        return DPS_OK;
    }

    /* If key ID doesn't exist, don't add a NULL key. */
    if (!key) {
        return DPS_OK;
    }

    /* Grow the entries array as needed. */
    if (KeyStoreGrow(refKS) != DPS_OK) {
        return DPS_ERR_RESOURCES;
    }

    /* Add the new entry. */
    entry = refKS->entries + refKS->entriesCount;
    DPS_KeyId id;
    if (!DPS_CopyKeyId(&id, keyId)) {
        return DPS_ERR_RESOURCES;
    }
    if (KeyStoreSetKey(entry, key) != DPS_OK) {
        DPS_ClearKeyId(&id);
        return DPS_ERR_RESOURCES;
    }
    entry->keyId = id;
    refKS->entriesCount++;
    return DPS_OK;
}

DPS_Status DPS_SetTrustedCA(DPS_KeyStore* keyStore, const char* ca)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;

    DPS_DBGTRACE();

    char *newCA = strndup(ca, MAX_CERT_LEN);
    if (!newCA) {
        return DPS_ERR_RESOURCES;
    }
    if (refKS->ca) {
        free(refKS->ca);
    }
    refKS->ca = newCA;
    return DPS_OK;
}

DPS_Status DPS_SetCertificate(DPS_KeyStore* keyStore, const char* cert, const char* key, const char* password)
{
    ReferenceKeyStore* refKS = (ReferenceKeyStore*)keyStore;
    char* cn = NULL;
    DPS_KeyId keyId;
    KeyStoreEntry* entry;

    DPS_DBGTRACE();

    if (!cert) {
        return DPS_ERR_ARGS;
    }

    cn = DPS_CertificateCN(cert);
    if (!cn) {
        goto ErrorExit;
    }
    keyId.len = strnlen(cn, DPS_MAX_KEY_ID_LEN);
    if (keyId.len == DPS_MAX_KEY_ID_LEN) {
        goto ErrorExit;
    }
    memcpy(keyId.id, cn, keyId.len + 1);

    /* Replace cert if id already exists. */
    entry = KeyStoreLookup(refKS, &keyId);
    if (entry) {
        if (SetCertificate(entry, cert, key, password) != DPS_OK) {
            goto ErrorExit;
        }
        return DPS_OK;
    }

    /* Grow the certificates array as needed. */
    if (KeyStoreGrow(refKS) != DPS_OK) {
        goto ErrorExit;
    }

    /* Add the new entry. */
    entry = refKS->entries + refKS->entriesCount;
    if (SetCertificate(entry, cert, key, password) != DPS_OK) {
        goto ErrorExit;
    }
    entry->keyId = keyId;
    refKS->entriesCount++;
    return DPS_OK;

ErrorExit:
    if (cn) {
        free(cn);
    }
    return DPS_ERR_RESOURCES;
}
