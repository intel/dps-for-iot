/**
 * @file
 * Public Key management APIs
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

#ifndef _KEY_MANAGEMENT_H
#define _KEY_MANAGEMENT_H

#include <stdint.h>
#include <stddef.h>
#include <dps/err.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_AES_256_KEY_LEN 32 /**< AES 256 key length, in bytes */

#define DPS_MAX_CERT_LEN 10240 /**< For sanity check on Cert length */
#define DPS_MAX_PK_LEN    1024 /**< For sanity check on PK length */
#define DPS_MAX_PWD_LEN   1024 /**< For sanity check on pass phrase length */

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
    const uint8_t* key;         /**< Key data */
    size_t len;                 /**< Size of key data */
} DPS_KeySymmetric;

/**
 * Allowed elliptic curves
 */
typedef enum {
    DPS_EC_CURVE_RESERVED = 0,
    DPS_EC_CURVE_P384 = 2, /**< NIST P-384 also known as secp384r1 */
    DPS_EC_CURVE_P521 = 3  /**< NIST P-521 also known as secp521r1 */
} DPS_ECCurve;

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
    const uint8_t* x; /**< X coordinate */
    const uint8_t* y; /**< Y coordinate */
    const uint8_t* d; /**< D coordinate */
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
    const uint8_t* id; /**< the identifier of the key */
    size_t len; /**< the length of the identifier, in bytes */
} DPS_KeyId;

/**
 * Opaque type for a key store.
 */
typedef struct _DPS_KeyStore DPS_KeyStore;

/**
 * Opaque type for a key store request.
 */
typedef struct _DPS_KeyStoreRequest DPS_KeyStoreRequest;

/**
 * Function prototype for a key store handler called when a key and
 * key identifier is requested.
 *
 * DPS_SetKeyAndId() should be called to provide the key and
 * identifier to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 *
 * @return
 * - DPS_OK when DPS_SetKeyAndId() succeeds
 * - DPS_ERR_MISSING when no key is configured for this host
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyAndIdHandler)(DPS_KeyStoreRequest* request);

/**
 * Function prototype for a key store handler called when a key with the provided
 * key identifier is requested.
 *
 * DPS_SetKey() should be called to provide the key to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 * @param keyId The identifier of the key to provide.
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyHandler)(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);

/**
 * Function prototype for a key store handler called when an ephemeral key with the
 * provided type is requested.
 *
 * DPS_SetKey() should be called to provide the ephemeral key to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 * @param key The requested key type and parameters (e.g. key->type is
 *            DPS_KEY_EC and key->ec.curve is DPS_EC_CURVE_P521).
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_EphemeralKeyHandler)(DPS_KeyStoreRequest* request, const DPS_Key* key);

/**
 * Function prototype for a key store handler called when the trusted
 * CA chain is requested.
 *
 * DPS_SetCA() should be called to provide the CA chain to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 *
 * @return
 * - DPS_OK when DPS_SetCA() succeeds
 * - DPS_ERR_MISSING when no CA chain is configured
 * - error otherwise
 */
typedef DPS_Status (*DPS_CAHandler)(DPS_KeyStoreRequest* request);


#ifdef __cplusplus
}
#endif

#endif
