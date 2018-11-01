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

#include <string.h>
#include <dps/dbg.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <dps/private/hkdf.h>
#include <dps/private/mbedtls.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_Status HKDF_SHA256(const uint8_t* secret, size_t secretLen,
                       const uint8_t* context, size_t contextLen,
                       uint8_t key[AES_256_KEY_LEN])
{
    mbedtls_md_context_t md;
    const mbedtls_md_info_t* info;
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    uint8_t count;
    int ret;

    mbedtls_md_init(&md);

    /*
     * Extract
     */
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_md_setup(&md, info, 1);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_starts(&md, NULL, 0);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_update(&md, secret, secretLen);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_finish(&md, digest);
    if (ret != 0) {
        goto Exit;
    }

    /*
     * Expand
     */
    ret = mbedtls_md_hmac_starts(&md, digest, mbedtls_md_get_size(info));
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_update(&md, context, contextLen);
    if (ret != 0) {
        goto Exit;
    }
    count = 1;
    ret = mbedtls_md_hmac_update(&md, &count, sizeof(count));
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_finish(&md, digest);
    if (ret != 0) {
        goto Exit;
    }
    memcpy(key, digest, AES_256_KEY_LEN);

Exit:
    mbedtls_md_free(&md);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
