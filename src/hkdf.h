/**
 * @file
 * HMAC-based extract-and-expand Key Derivation Function
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

#ifndef _HKDF_H
#define _HKDF_H

#include <dps/private/dps.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Applies an HMAC-based extract-and-expand Key Derivation Function to
 * generate a key.
 *
 * @param secret the secret
 * @param secretLen the size of the secret, in bytes
 * @param context the context for the hash function
 * @param contextLen the size of the hash context, in bytes
 * @param key returns the generated key
 *
 * @return
 *         - DPS_OK if the key is generated
 *         - DPS_ERR_INVALID if the key cannot be generated
 */
DPS_Status HKDF_SHA256(const uint8_t* secret, size_t secretLen,
                       const uint8_t* context, size_t contextLen,
                       uint8_t key[AES_256_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif
