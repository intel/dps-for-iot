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
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Size of the nonce
 */
#define COSE_NONCE_LEN        13

/*
 * Algorithms currently supported by this implementation.
 *
 * These values are defined in the COSE specification.
 */
#define COSE_ALG_RESERVED               0
#define COSE_ALG_AES_CCM_16_64_128     10    /**< AES-CCM mode 128-bit key, L=16, M=64,  13-byte nonce, 8 byte auth tag */
#define COSE_ALG_AES_CCM_16_128_128    30    /**< AES-CCM mode 128-bit key, L=16, M=128, 13-byte nonce, 16 byte auth tag */
#define COSE_ALG_A128KW                -3    /**< AES Key Wrap w/ 128-bit key */
#define COSE_ALG_DIRECT                -6    /**< Direct use of CEK */
#define COSE_ALG_ES256                 -7    /**< ECDSA w/ SHA-256 */
#define COSE_ALG_ECDH_ES_HKDF_256     -25    /**< ECDH ES w/ HKDF */
#define COSE_ALG_ECDH_ES_A128KW       -29    /**< ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key */
#define COSE_ALG_ES384                -35    /**< ECDSA w/ SHA-384 */
#define COSE_ALG_ES512                -36    /**< ECDSA w/ SHA-512 */

/**
 * COSE recipient or signer information used in message encryption,
 * decryption, and key requests.
 */
typedef struct _COSE_Entity {
    int8_t alg;         /**< Recipient or signature algorithm */
    const uint8_t* kid; /**< Key identifier */
    size_t kidLen;      /**< Size of key identifier, in bytes */
} COSE_Entity;

/**
 * Union of supported key types.
 */
typedef struct _COSE_Key {
    enum {
        COSE_KEY_SYMMETRIC,
        COSE_KEY_EC
    } type; /**< Type of key */
    union {
        struct {
            uint8_t key[AES_128_KEY_LEN];   /**< Key data */
        } symmetric; /**< Symmetric key */
        struct {
            int8_t curve; /**< EC curve */
            uint8_t x[EC_MAX_COORD_LEN]; /**< X coordinate */
            uint8_t y[EC_MAX_COORD_LEN]; /**< Y coordinate */
            uint8_t d[EC_MAX_COORD_LEN]; /**< D coordinate */
        } ec; /**< Elliptic curve key */
    };
} COSE_Key;

/**
 * Function prototype for callback function for requesting the encryption key
 * for a specific key identifier.  This function must not block.
 *
 * @param ctx     Caller provided context
 * @param alg     The crypto algorithm to use
 * @param kid     The key identifier, NULL to request a random key
 * @param kidLen  The size of the key identifier in bytes, 0 to request a random key
 * @param key     Buffer for returning the key.
 *
 * @return  DPS_OK if a key matching the kid was returned
 *          DPS_ERR_MSSING if there is no matchin key
 */
typedef DPS_Status (*COSE_KeyRequest)(void* ctx, int8_t alg, const uint8_t* kid, size_t kidLen, COSE_Key* key);

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
 * @param keyCB          Callback function called to request the encryption key
 * @param ctx            Context to be passed to the key request callback
 * @param cipherText     Buffer for returning the authenticated and encrypted output. The storage for this
 *                       buffer is allocated by this function and must be freed by the caller.
 *
 * @return  - DPS_OK if the plaintext was succesfully encrypted
 *          - Other error codes
 */
DPS_Status COSE_Encrypt(int8_t alg,
                        const uint8_t nonce[COSE_NONCE_LEN],
                        const COSE_Entity* signer,
                        const COSE_Entity* recipient, size_t recipientLen,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* plainText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        DPS_TxBuffer* cipherText);

/**
 * COSE Decryption
 *
 * @param nonce      The nonce.  May be NULL if the nonce is contained in the payload.
 * @param recipient  Returns the recipient information used to succesfully lookup the decryption key.
 *                   Note that this points into cipherText so care must be taken to avoid
 *                   referencing freed memory.
 * @param aad        Buffer containing the external auxiliary authenticated data.
 * @param cipherText Buffer containing the authenticated and encrypted input data
 * @param keyCB      Callback function called to request the encryption key
 * @param ctx        Context to be passed to the key request callback
 * @param recipient  Returns the recipient information used to succesfully verify the signed cipherText.
 *                   Note that this points into cipherText so care must be taken to avoid
 *                   referencing freed memory.
 * @param plainText  Buffer for returning the decrypted payload. The storage for this
 *                   buffer is allocated by this function and must be freed by the caller.
 *
 * @return  - DPS_OK if the payload was succesfully decrypted
 *          - DPS_ERR_NOT_ENCRYPTED if the payload is not a COSE payload (no COSE tag)
 *          - DPS_ERR_INVALID if the payload is badly formed
 *          - DPS_ERR_SECURITY if the payload failed to decrypt
 *          - Other error codes
 */
DPS_Status COSE_Decrypt(const uint8_t* nonce,
                        COSE_Entity* recipient,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* cipherText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        COSE_Entity* signer,
                        DPS_TxBuffer* plainText);

#ifdef __cplusplus
}
#endif

#endif
