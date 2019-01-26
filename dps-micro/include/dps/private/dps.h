/**
 * @file
 * Internal APIs
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

#ifndef _DPS_INTERNAL_H
#define _DPS_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <dps/dps.h>
#include <dps/private/io_buf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A_SIZEOF(x)   (sizeof(x) / sizeof((x)[0]))

/*
 * Map keys for CBOR serialization of DPS messages
 */
#define DPS_CBOR_KEY_PORT           1   /**< uint */
#define DPS_CBOR_KEY_TTL            2   /**< int */
#define DPS_CBOR_KEY_PUB_ID         3   /**< bstr (UUID) */
#define DPS_CBOR_KEY_SEQ_NUM        4   /**< uint */
#define DPS_CBOR_KEY_ACK_REQ        5   /**< bool */
#define DPS_CBOR_KEY_BLOOM_FILTER   6   /**< bstr */
#define DPS_CBOR_KEY_SUB_FLAGS      7   /**< uint */
#define DPS_CBOR_KEY_MESH_ID        8   /**< bstr (UUID) */
#define DPS_CBOR_KEY_NEEDS          9   /**< bstr */
#define DPS_CBOR_KEY_INTERESTS     10   /**< bstr */
#define DPS_CBOR_KEY_TOPICS        11   /**< array (tstr) */
#define DPS_CBOR_KEY_DATA          12   /**< bstr */
#define DPS_CBOR_KEY_ACK_SEQ_NUM   13   /**< uint */

#ifdef __cplusplus
}
#endif

#endif
