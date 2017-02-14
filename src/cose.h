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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Size of the nonce
 */
#define DPS_COSE_NONCE_SIZE        13

/**
 * Key length
 */
#define AES_128_KEY_LEN       16

/*
 * Symmetric cipher modes and configurations currently supported by this implementation
 *
 * These values are defined in the COSE specification
 */
#define AES_CCM_16_64_128     10    /**< AES-CCM mode 128-bit key, L=16, M=64,  13-byte nonce, 8 byte auth tag */
#define AES_CCM_16_128_128    30    /**< AES-CCM mode 128-bit key, L=16, M=128, 13-byte nonce, 16 byte auth tag*/

/**
 * Function prototype for callback function for requesting the encryption key
 * for a specific key identifier. This function must not block
 *
 * @param ctx   Caller provided context
 * @param alg   The symmetric crypto algorithm variant to use
 * @param kid   The key identifier
 * @param key   Buffer for returning the key.
 *
 * @return  DPS_OK if a key matching the kid was returned
 *          DPS_ERR_MSSING if there is no matchin key
 */
typedef DPS_Status (*COSE_KeyRequest)(void* ctx, const DPS_UUID* kid, int8_t alg, uint8_t key[AES_128_KEY_LEN]);

/**
 * COSE Encryption
 *
 * @param alg        The symmetric crypto algorithm variant to use
 * @param kid        The key identifier
 * @param nonce      The nonce
 * @param aad        Buffer containing the external auxiliary authenticated data
 * @param plainText  Buffer containing the plain text payload to be encrypted
 * @param keyCB      Callback function called to request the encryption key
 * @param ctx        Context to be passed to the key request callback
 * @param cipherText Buffer for returning the authenticated and encrypted output. The storage for this
 *                   buffer is allocated by this function and must be freed by the caller.
 *
 * @return  - DPS_OK if the plaintext was succesfully encrypted
 *          - Other error codes
 */
DPS_Status COSE_Encrypt(int8_t alg,
                        const DPS_UUID* kid,
                        const uint8_t nonce[DPS_COSE_NONCE_SIZE],
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* plainText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        DPS_TxBuffer* cipherText);

/**
 * COSE Decryption
 *
 * @param nonce      The nonce
 * @param kid        Returns the key identifier used to lookup the decryption key.
 * @param aad        Buffer containing the external auxiliary authenticated data.
 * @param cipherText Buffer containing the authenticated and encrypted input data
 * @param keyCB      Callback function called to request the encryption key
 * @param ctx        Context to be passed to the key request callback
 * @param plainText  Buffer for returning the decrypted payload. The storage for this
 *                   buffer is allocated by this function and must be freed by the caller.
 *
 * @return  - DPS_OK if the payload was succesfully decrypted
 *          - DPS_ERR_NOT_ENCRYPTED if the payload is not a COSE payload (no COSE tag)
 *          - DPS_ERR_INVALID if the payload is badly formed
 *          - DPS_ERR_SECURITY if the payload failed to decrypt
 *          - Other error codes
 */
DPS_Status COSE_Decrypt(const uint8_t nonce[DPS_COSE_NONCE_SIZE],
                        DPS_UUID* kid,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* cipherText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        DPS_TxBuffer* plainText);


#ifdef __cplusplus
}
#endif

#endif
