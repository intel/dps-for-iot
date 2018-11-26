/**
 * @file
 * Encrypt and decrypt COSE messages
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

#ifndef _COSE_H
#define _COSE_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include "gcm.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Size of the nonce
 */
#define COSE_NONCE_LEN        AES_GCM_NONCE_LEN

/*
 * Algorithms currently supported by this implementation.
 *
 * These values are defined in the COSE specification.
 */
#define COSE_ALG_RESERVED               0    /**< Reserved algorithm value */
#define COSE_ALG_A256GCM                3    /**< AES-GCM mode w/ 256-bit key, 128-bit tag */
#define COSE_ALG_A256KW                -5    /**< AES Key Wrap w/ 256-bit key */
#define COSE_ALG_DIRECT                -6    /**< Direct use of CEK */
#define COSE_ALG_ECDH_ES_A256KW       -31    /**< ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key */
#define COSE_ALG_ES384                -35    /**< ECDSA w/ SHA-384 */
#define COSE_ALG_ES512                -36    /**< ECDSA w/ SHA-512 */

/**
 * COSE recipient or signer information used in message encryption,
 * decryption, and key requests.
 */
typedef struct _COSE_Entity {
    int8_t alg;         /**< Recipient or signature algorithm */
    DPS_KeyId kid;      /**< Key identifier */
} COSE_Entity;

/**
 * COSE Encryption
 *
 * @param alg            The symmetric crypto algorithm variant to use
 * @param nonce          The nonce
 * @param signer         The signer information, may be NULL
 * @param recipient      The recipient information
 * @param recipientLen   The number of recipients
 * @param aad            Buffer containing the external auxiliary authenticated data
 * @param plainText      Buffer containing the plain text payload to be encrypted
 * @param keyStore       Request handler for encryption keys
 * @param cipherText     Buffer for returning the authenticated and encrypted output. The storage for this
 *                       buffer is allocated by this function and must be freed by the caller.
 *
 * @return
 * - DPS_OK if the plaintext was successfully encrypted
 * - Other error codes
 */
DPS_Status COSE_Encrypt(DPS_Node* node,
                        int8_t alg,
                        const uint8_t nonce[COSE_NONCE_LEN],
                        const COSE_Entity* signer,
                        const COSE_Entity* recipient, size_t recipientLen,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* plainText,
                        DPS_KeyStore* keyStore,
                        DPS_TxBuffer* cipherText);

/**
 * COSE Decryption
 *
 * @param nonce      The nonce.  May be NULL if the nonce is contained in the payload.
 * @param recipient  Returns the recipient information used to successfully lookup the decryption key.
 *                   Note that this points into cipherText so care must be taken to avoid
 *                   referencing freed memory.
 * @param aad        Buffer containing the external auxiliary authenticated data.
 * @param cipherText Buffer containing the authenticated and encrypted input data
 * @param keyStore   Request handler for encryption keys
 * @param signer     Returns the recipient information used to successfully verify the signed cipherText.
 *                   Note that this points into cipherText so care must be taken to avoid
 *                   referencing freed memory.  This will be memset to 0 if not verified.
 * @param plainText  Buffer for returning the decrypted payload. The storage for this
 *                   buffer is allocated by this function and must be freed by the caller.
 *
 * @return
 * - DPS_OK if the payload was successfully decrypted
 * - DPS_ERR_NOT_ENCRYPTED if the payload is not a COSE payload (no COSE tag)
 * - DPS_ERR_INVALID if the payload is badly formed
 * - DPS_ERR_SECURITY if the payload failed to decrypt
 * - Other error codes
 */
DPS_Status COSE_Decrypt(DPS_Node* node,
                        const uint8_t* nonce,
                        COSE_Entity* recipient,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* cipherText,
                        DPS_KeyStore* keyStore,
                        COSE_Entity* signer,
                        DPS_TxBuffer* plainText);

#ifdef __cplusplus
}
#endif

#endif
