/**
 * @file
 * AES key wrap algorithm
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

#ifndef _KEYWRAP_H
#define _KEYWRAP_H

#include <dps/err.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_256_KEY_WRAP_LEN 40 /**< The length of the wrapped AES-256 key in bytes */

/**
 * Wrap a key per the algorithm specified in RFC 3394.
 *
 * @param cek the content encryption key (aka the plaintext)
 * @param kek the key encryption key
 * @param cipherText returns the wrapped content encryption key
 *
 * @return DPS_OK if wrapped, an error otherwise
 */
DPS_Status KeyWrap(const uint8_t cek[AES_256_KEY_LEN], const uint8_t kek[AES_256_KEY_LEN],
                   uint8_t cipherText[AES_256_KEY_WRAP_LEN]);

/**
 * Unwrap a key per the algorithm specified in RFC 3394.
 *
 * @param cipherText the wrapped content encryption key
 * @param kek the key encryption key
 * @param cek returns the content encryption key (aka the plaintext)
 *
 * @return DPS_OK if unwrapped, an error otherwise
 */
DPS_Status KeyUnwrap(const uint8_t cipherText[AES_256_KEY_WRAP_LEN], const uint8_t kek[AES_256_KEY_LEN],
                     uint8_t cek[AES_256_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif
