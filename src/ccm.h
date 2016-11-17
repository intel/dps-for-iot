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

#define AES_128_KEY_LENGTH   16

/*
 * This is the recommended nonce size for COSE and the only
 * size that is supported in the DPS implementation. This
 * in turn implies a two byte length field for the encrypted
 * payload.
 */
#define DPS_CCM_NONCE_SIZE   13

/**
 * Implements AES-CCM (Counter with CBC-MAC) encryption as described in RFC 3610. The message in
 * encrypted in place.
 *
 * @param key     The AES-128 encryption key
 * @param M       Length of the authentication tag in bytes (even numbers 4..16)
 * @param L       Bytes for encoding the length (must be 2 in this implementation)
 * @param nonce   The nonce (must be 13 bytes in this implementation)
 * @param msg     Plaintext to be encrypted, The buffer must have room at the end to append
 *                authentication tag of length M bytes.
 * @param msgLen  The length of the plaintext
 * @param aad     The auxiliary data that will be authenticated but not encrypted
 * @param aadLen  The length of the auxiliary data
 *
 * @return
 *         - DPS_OK if the CCM context is initialized
 *         - DPS_ERR_RESOURCES if the resources required are not available.
 */
DPS_Status Encrypt_CCM(const uint8_t key[AES_128_KEY_LENGTH],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[DPS_CCM_NONCE_SIZE],
                       uint8_t* msg,
                       uint32_t msgLen,
                       const uint8_t* aad,
                       uint32_t aadLen);

/**
 * Implements AES-CCM (Counter with CBC-MAC) decryption as described in RFC 3610. The message in
 * decrypted in place.
 *
 * @param key     The AES-128 encryption key
 * @param M       Length of the authentication tag in bytes (even numbers 4..16)
 * @param L       Bytes for encoding the length (must be 2 in this implementation)
 * @param nonce   The nonce (must be 13 bytes in this implementation)
 * @param msg     The buffer containing the cryptext for the message.
 * @param msgLen  The length of the cryptext
 * @param aad     The auxiliary data that will be authenticated but not encrypted
 * @param aadLen  The length of the auxiliary data
 *
 * @return
 *         - DPS_OK if the CCM context is initialized
 *         - DPS_ERR_RESOURCES if the resources required are not available.
 *         - DPS_ERR_SECURITY if the decryption failed
 */
DPS_Status Decrypt_CCM(const uint8_t key[AES_128_KEY_LENGTH],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[DPS_CCM_NONCE_SIZE],
                       uint8_t* msg,
                       uint32_t msgLen,
                       const uint8_t* aad,
                       uint32_t aadLen);


#endif
