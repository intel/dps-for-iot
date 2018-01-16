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

#include <dps/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Preshared keys and certificates for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */

extern DPS_UUID NetworkKeyId;
extern uint8_t NetworkKey[16];

#define NUM_KEYS 2

extern DPS_UUID PskId[NUM_KEYS];
extern uint8_t PskData[NUM_KEYS][16];

extern const char TrustedCAs[];

extern const char PublisherId[];
extern const char PublisherCert[];
extern const char PublisherPrivateKey[];
extern const char PublisherPassword[];

extern const char SubscriberId[];
extern const char SubscriberCert[];
extern const char SubscriberPrivateKey[];
extern const char SubscriberPassword[];

#ifdef __cplusplus
}
#endif

#endif
