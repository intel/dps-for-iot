/**
 * @file
 * Common cryptographic macros and functions
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "dps.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_256_KEY_LEN 32 /**< AES 256 key length, in bytes */

#define EC_MAX_COORD_LEN 66 /**< Maximum length of an EC coordinate (x, y, or d) */

/**
 * Opaque type of random byte generator
 */
typedef struct _DPS_RBG DPS_RBG;

/**
 * Create an instance of a random byte generator
 *
 * @return the random byte generator
 */
DPS_RBG* DPS_CreateRBG();

/**
 * Destroy a previously-created instance of a random byte generator
 *
 * @param rbg the random byte generator
 */
void DPS_DestroyRBG(DPS_RBG* rbg);

/**
 * Create a random AES key
 *
 * @param rbg a random byte generator
 * @param key the created key
 *
 * @return DPS_OK if creation is successful, an error otherwise
 */
DPS_Status DPS_RandomKey(DPS_RBG *rbg, uint8_t key[AES_256_KEY_LEN]);

/**
 * Create an ephemeral elliptic curve key
 *
 * @param rbg a random byte generator
 * @param curve a named curve
 * @param x the created key's x coordinate
 * @param y the created key's y coordinate
 * @param d the created key's d coordinate
 *
 * @return DPS_OK if creation is successful, an error otherwise
 */
DPS_Status DPS_EphemeralKey(DPS_RBG* rbg, DPS_ECCurve curve,
                            uint8_t x[EC_MAX_COORD_LEN], uint8_t y[EC_MAX_COORD_LEN],
                            uint8_t d[EC_MAX_COORD_LEN]);

/**
 * Decode the common name (CN) attribute of an X.509 certificate.
 *
 * @param cert the X.509 certificate
 *
 * @return the CN value, must be freed by the caller.
 */
char* DPS_CertificateCN(const char* cert);

#ifdef __cplusplus
}
#endif

#endif
