/**
 * @file
 * AES-CCM encryption and decryption
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

#ifndef _CCM_H
#define _CCM_H

#include <stdint.h>
#include <dps/dbg.h>
#include <dps/err.h>
#include <dps/private/dps.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This is the recommended nonce size for COSE and the only
 * size that is supported in the DPS implementation. This
 * in turn implies a two byte length field for the encrypted
 * payload.
 */
#define AES_CCM_NONCE_LEN   13

/**
 * Implements AES-CCM (Counter with CBC-MAC) encryption as described in RFC 3610. The message is
 * encrypted in place.
 *
 * @param key        The AES-128 encryption key
 * @param M          Length of the authentication tag in bytes (even numbers 4..16)
 * @param L          Bytes for encoding the length (must be 2 in this implementation)
 * @param nonce      The nonce (must be 13 bytes in this implementation)
 * @param plainText  Plaintext to be encrypted,
 * @param ptLen      The length of the plaintext
 * @param aad        The auxiliary data that will be authenticated but not encrypted
 * @param aadLen     The length of the auxiliary data
 * @param cipherText Returns the cipher text. The buffer must have room to append
 *                   (ptLen + M) bytes.
 *
 * @return
 * - DPS_OK if the CCM context is initialized
 * - DPS_ERR_RESOURCES if the resources required are not available.
 */
DPS_Status Encrypt_CCM(const uint8_t key[AES_128_KEY_LEN],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[AES_CCM_NONCE_LEN],
                       const uint8_t* plainText,
                       size_t ptLen,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* cipherText);

/**
 * Implements AES-CCM (Counter with CBC-MAC) decryption as described in RFC 3610. The message is
 * decrypted in place.
 *
 * @param key        The AES-128 encryption key
 * @param M          Length of the authentication tag in bytes (even numbers 4..16)
 * @param L          Bytes for encoding the length (must be 2 in this implementation)
 * @param nonce      The nonce (must be 13 bytes in this implementation)
 * @param cipherText The cipher text to be decrypted
 * @param ctLen      The length of the cipher text
 * @param aad        The auxiliary data that will be authenticated but not encrypted
 * @param aadLen     The length of the auxiliary data
 * @param plainText  Returns the decrypted plain text. The buffer must have room
 *                   to append (ctLen - M) bytes.
 *
 * @return
 * - DPS_OK if the CCM context is initialized
 * - DPS_ERR_RESOURCES if the resources required are not available.
 * - DPS_ERR_SECURITY if the decryption failed
 */
DPS_Status Decrypt_CCM(const uint8_t key[AES_128_KEY_LEN],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[AES_CCM_NONCE_LEN],
                       const uint8_t* cipherText,
                       size_t ctLen,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* plainText);

#ifdef __cplusplus
}
#endif

#endif
