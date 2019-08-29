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

#include <safe_lib.h>
#include <string.h>
#include <dps/dbg.h>
#include "mbedtls/hkdf.h"
#include "hkdf.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

DPS_Status HKDF_SHA256(const uint8_t* secret, size_t secretLen,
                       const uint8_t* context, size_t contextLen,
                       uint8_t key[AES_256_KEY_LEN])
{
    const mbedtls_md_info_t* info;
    int ret;

    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_hkdf(info, NULL, 0, secret, secretLen, context, contextLen, key, AES_256_KEY_LEN);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
