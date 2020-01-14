/**
 * @file
 * Public keystore APIs
 */

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

#ifndef _KEYSTORE_H
#define _KEYSTORE_H

#include <dps/err.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DPS_Node DPS_Node;

#define DPS_AES_256_KEY_LEN 32 /**< AES 256 key length, in bytes */

#define DPS_MAX_CERT_LEN 10240 /**< For sanity check on Cert length */
#define DPS_MAX_PK_LEN    1024 /**< For sanity check on PK length */
#define DPS_MAX_PWD_LEN   1024 /**< For sanity check on pass phrase length */

#define DPS_MAX_SYMMETRIC_KEY_LEN DPS_AES_256_KEY_LEN

/**
 * Configuration parameter - needs to configured to be large enough
 * for the maximum key id used by the local application.
 */
#define DPS_MAX_KEY_ID_LEN  32

/**
 * Configuration parameter for maximum size of the keystore
 */
#define DPS_MAX_KEYSTORE_ENTRIES 8

/**
 * A DPS key type
 */
typedef enum {
    DPS_KEY_SYMMETRIC,          /**< DPS_KeySymmetric */
    DPS_KEY_EC,                 /**< DPS_KeyEC */
    DPS_KEY_EC_CERT             /**< DPS_KeyCert */
} DPS_KeyType;

/**
 * Symmetric key data
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeySymmetric {
    uint8_t key[DPS_MAX_SYMMETRIC_KEY_LEN]; /**< Key data */
    size_t len;                             /**< Size of key data */
} DPS_KeySymmetric;

/**
 * Allowed elliptic curves
 */
typedef enum {
    DPS_EC_CURVE_RESERVED = 0,
    DPS_EC_CURVE_P384 = 2, /**< NIST P-384 also known as secp384r1 */
    DPS_EC_CURVE_P521 = 3  /**< NIST P-521 also known as secp521r1 */
} DPS_ECCurve;

#define DPS_EC_MAX_COORD_LEN 66 /**< Maximum length of an EC coordinate (x, y, or d) */

/**
 * Elliptic curve key data.
 *
 * Only @p x and @p y are needed for a public key.  Similarly, only @p
 * d is needed for a private key.
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeyEC {
    DPS_ECCurve curve; /**< The named curve */
    uint8_t x[DPS_EC_MAX_COORD_LEN]; /**< X coordinate */
    uint8_t y[DPS_EC_MAX_COORD_LEN]; /**< Y coordinate */
    uint8_t d[DPS_EC_MAX_COORD_LEN]; /**< D coordinate */
} DPS_KeyEC;

/**
 * Certificate key data.
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeyCert {
    const char *cert;           /**< The certificate in PEM format */
    const char *privateKey;     /**< The optional private key in PEM format */
    const char *password;       /**< The optional password protecting the key */
} DPS_KeyCert;

/**
 * Union of supported key types.
 */
typedef struct _DPS_Key {
    DPS_KeyType type; /**< Type of key */
    /** Value of key */
    union {
        DPS_KeySymmetric symmetric; /**< DPS_KEY_SYMMETRIC */
        DPS_KeyEC ec;               /**< DPS_KEY_EC */
        DPS_KeyCert cert;           /**< DPS_KEY_EC_CERT */
    };
} DPS_Key;

/**
 * An identifier of a key in a key store.
 */
typedef struct _DPS_KeyId {
    char id[DPS_MAX_KEY_ID_LEN]; /**< the identifier of the key */
    size_t len;                  /**< the length of the identifier, in bytes */
} DPS_KeyId;

/**
 * Type for a key store.
 */
typedef struct _DPS_KeyStore DPS_KeyStore;

/**
 * Create or replace a key with the specified key identifier in the key store.
 *
 * Specify a previously set key identifier and a NULL key to remove a key from the key store.
 *
 * @param keyStore A key store
 * @param keyId The identifier of the key to create, replace, or remove
 * @param key The key
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetContentKey(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key);

/**
 * Create or replace the network key in the key store.
 *
 * @param keyStore A key store
 * @param keyId The identifier of the key to create
 * @param key The key
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetNetworkKey(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key);

/**
 * Create or replace the trusted CA(s) in the key store.
 *
 * @param keyStore   The key store to access
 * @param ca The CA chain in PEM format
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetTrustedCA(DPS_KeyStore* keyStore, const char* ca);

/**
 * Create or replace a certificate in the key store.
 *
 * @param mks An in-memory key store
 * @param cert The certificate in PEM format
 * @param key The optional private key in PEM format
 * @param password The optional password protecting the key, may be NULL
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetCertificate(DPS_KeyStore* keyStore,
                              const char* cert,
                              const char* key,
                              const char* password);

/** 
 * Protoype for callback function called to deliver a key to the requestor.
 *
 * @param  key     The key being delivered
 * @param  keyId   The key identifier or NULL for ephemeral keys
 * @param  data    Upper layer data provided to the request call
 */
typedef DPS_Status (*DPS_KeyResponse)(const DPS_Key* key, const DPS_KeyId* keyId, void* data);

/** 
 * Protoype for callback function called to deliver the CA chain to the requestor
 */
typedef DPS_Status (*DPS_CAChainResponse)(const char* ca, void* data);

/**
 * Protoype for callback function called to deliver a certificate to the requestor
 */
typedef DPS_Status (*DPS_CertResponse)(const char* cert,
                                       size_t certLen, 
                                       const char* key, 
                                       size_t keyLen,
                                       const char* pwd,
                                       size_t pwdLen,
                                       void* data);

/**
 * Function prototype for a key store handler called when a key with the provided
 * key identifier is requested.
 *
 * DPS_SetKey() should be called to provide the key to the caller.
 *
 * @param keyId The identifier of the key to provide.
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyRequest)(DPS_KeyStore* keyStore, const DPS_KeyId* keyId, DPS_KeyResponse response, void* data);

/**
 * Function prototype for a key store handler called when a pre-shared
 * key and corresponding key identifier is requested.
 *
 * @return
 * - DPS_OK when DPS_SetKeyAndId() succeeds
 * - DPS_ERR_MISSING when no key is configured for this host
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyAndIdRequest)(DPS_KeyStore* keyStore, DPS_KeyResponse response, void* data);

/**
 * Function prototype for a key store handler called when an ephemeral key with the
 * provided type is requested.
 *
 * DPS_SetKey() should be called to provide the ephemeral key to the caller.
 *
 * @param key The requested key type and parameters (e.g. key->type is
 *            DPS_KEY_EC and key->ec.curve is DPS_EC_CURVE_P521).
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_EphemeralKeyRequest)(DPS_KeyStore* keyStore, const DPS_Key* key, DPS_KeyResponse response, void* data); 

/**
 * Function prototype for a key store handler called when the trusted
 * CA chain is requested.
 *
 * DPS_SetCA() should be called to provide the CA chain to the caller.
 *
 * @return
 * - DPS_OK when DPS_SetCA() succeeds
 * - DPS_ERR_MISSING when no CA chain is configured
 * - error otherwise
 */
typedef DPS_Status (*DPS_CAChainRequest)(DPS_KeyStore* keyStore, DPS_CAChainResponse response, void* data);

/**
 * Abstract interface for a key store.
 */
struct _DPS_KeyStore {
    DPS_KeyAndIdRequest keyAndIdRequest;         /**< Called when a key and key identifier is requested */
    DPS_KeyRequest keyRequest;                   /**< Called when a key is requested */
    DPS_EphemeralKeyRequest ephemeralKeyRequest; /**< Called when an ephemeral key is requested */
    DPS_CAChainRequest caChainRequest;           /**< Called when a CA chain is requested */
};

/**
  * Create a key store
  */
DPS_KeyStore* DPS_CreateKeyStore();

/**
  * Destroy a key store
  */
void DPS_DestroyKeyStore(DPS_KeyStore* keyStore);

/**
 * Returns the @p DPS_KeyStore* for the node
 *
 * @param keyStore A key store
 *
 * @return The DPS_KeyStore* or NULL
 */
DPS_KeyStore* DPS_GetKeyStore(DPS_Node* node);

/**
 * Copy a DPS_KeyId
 *
 * @param dest The key ID to copy to
 * @param src  The key ID to copy from
 *
 * @return dest on success or NULL on failure
 */
DPS_KeyId* DPS_CopyKeyId(DPS_KeyId* dest, const DPS_KeyId* src);

/**
 * Release memory used by the key ID.
 *
 * @param keyId The key ID
 */
void DPS_ClearKeyId(DPS_KeyId* keyId);


/** @} */ /* end of subscription group */

#ifdef __cplusplus
}
#endif

#endif
