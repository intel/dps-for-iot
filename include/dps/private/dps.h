/**
 * @file
 * Internal APIs
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

#ifndef _DPS_INTERNAL_H
#define _DPS_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <dps/dps.h>
#include <dps/private/io_buf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A_SIZEOF(x)   (sizeof(x) / sizeof((x)[0]))

/*
 * Map keys for CBOR serialization of DPS messages
 */
#define DPS_CBOR_KEY_PORT           1   /**< uint */
#define DPS_CBOR_KEY_TTL            2   /**< int */
#define DPS_CBOR_KEY_PUB_ID         3   /**< bstr (UUID) */
#define DPS_CBOR_KEY_SEQ_NUM        4   /**< uint */
#define DPS_CBOR_KEY_ACK_REQ        5   /**< bool */
#define DPS_CBOR_KEY_BLOOM_FILTER   6   /**< bstr */
#define DPS_CBOR_KEY_SUB_FLAGS      7   /**< uint */
#define DPS_CBOR_KEY_MESH_ID        8   /**< bstr (UUID) */
#define DPS_CBOR_KEY_NEEDS          9   /**< bstr */
#define DPS_CBOR_KEY_INTERESTS     10   /**< bstr */
#define DPS_CBOR_KEY_TOPICS        11   /**< array (tstr) */
#define DPS_CBOR_KEY_DATA          12   /**< bstr */
#define DPS_CBOR_KEY_ACK_SEQ_NUM   13   /**< uint */

/**
 * A key store request.
 */
struct _DPS_KeyStoreRequest {
    DPS_KeyStore* keyStore; /**< The key store this request is directed to */
    void* data; /**< The caller provided request data */
    /** Called to provide a key and key identifier to the requestor */
    DPS_Status (*setKeyAndId)(DPS_KeyStoreRequest* request, const DPS_Key* key, const DPS_KeyId* keyId);
    /** Called to provide a key to the requestor */
    DPS_Status (*setKey)(DPS_KeyStoreRequest* request, const DPS_Key* key);
    /** Called to provide the CA chain to the requestor */
    DPS_Status (*setCA)(DPS_KeyStoreRequest* request, const char* ca);
    /** Called to provide a certificate to the requestor */
    DPS_Status (*setCert)(DPS_KeyStoreRequest* request, const char* cert, size_t certLen, const char* key, size_t keyLen, const char* pwd, size_t pwdLen);
};

/**
 * A key store.
 */
struct _DPS_KeyStore {
    void* userData;                              /**< The application provided user data */
    DPS_KeyAndIdHandler keyAndIdHandler;         /**< Called when a key and key identifier is requested */
    DPS_KeyHandler keyHandler;                   /**< Called when a key is requested */
    DPS_EphemeralKeyHandler ephemeralKeyHandler; /**< Called when an ephemeral key is requested */
    DPS_CAHandler caHandler;                     /**< Called when a CA chain is requested */
};


#ifdef __cplusplus
}
#endif

#endif
