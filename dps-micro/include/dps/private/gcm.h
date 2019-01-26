/**
 * @file
 * AES-CCM encryption and decryption
 */

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

#ifndef _GCM_H
#define _GCM_H

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
 * size that is supported in the DPS implementation.
 */
#define AES_GCM_NONCE_LEN   12

/**
 * Implements AES-GCM (Galois/Counter Mode) encryption. The message is
 * encrypted in place.
 *
 * @param key        The AES-256 encryption key
 * @param nonce      The nonce (must be 12 bytes in this implementation)
 * @param plainText  Plaintext to be encrypted,
 * @param ptLen      The length of the plaintext
 * @param aad        The auxiliary data that will be authenticated but not encrypted
 * @param aadLen     The length of the auxiliary data
 * @param cipherText Returns the cipher text. The buffer must have room to append
 *                   (ptLen + 16) bytes.
 *
 * @return
 * - DPS_OK if the GCM context is initialized
 * - DPS_ERR_RESOURCES if the resources required are not available.
 */
DPS_Status Encrypt_GCM(const uint8_t key[AES_256_KEY_LEN],
                       const uint8_t nonce[AES_GCM_NONCE_LEN],
                       const uint8_t* plainText,
                       size_t ptLen,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* cipherText);

/**
 * Implements AES-GCM (Galois/Counter Mode) decryption. The message is
 * decrypted in place.
 *
 * @param key        The AES-256 encryption key
 * @param nonce      The nonce (must be 12 bytes in this implementation)
 * @param cipherText The cipher text to be decrypted
 * @param ctLen      The length of the cipher text
 * @param aad        The auxiliary data that will be authenticated but not encrypted
 * @param aadLen     The length of the auxiliary data
 * @param plainText  Returns the decrypted plain text. The buffer must have room
 *                   to append (ctLen - 16) bytes.
 *
 * @return
 * - DPS_OK if the GCM context is initialized
 * - DPS_ERR_RESOURCES if the resources required are not available.
 * - DPS_ERR_SECURITY if the decryption failed
 */
DPS_Status Decrypt_GCM(const uint8_t key[AES_256_KEY_LEN],
                       const uint8_t nonce[AES_GCM_NONCE_LEN],
                       const uint8_t* cipherText,
                       size_t ctLen,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* plainText);

#ifdef __cplusplus
}
#endif

#endif
