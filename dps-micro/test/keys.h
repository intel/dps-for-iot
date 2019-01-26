/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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

#ifndef _KEYS_H
#define _KEYS_H

#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/keystore.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Preshared keys and certificates for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */

extern const DPS_KeyId NetworkKeyId;
extern const DPS_Key NetworkKey;

#define NUM_KEYS 2

extern const DPS_KeyId PskId[NUM_KEYS];
extern const DPS_Key Psk[NUM_KEYS];

extern const char TrustedCAs[];

typedef struct _Id {
    DPS_KeyId keyId;
    const char* cert;
    const char* privateKey;
    const char* password;
} Id;

extern const Id Ids[];

#ifdef __cplusplus
}
#endif

#endif
