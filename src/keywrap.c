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
#include "mbedtls/nist_kw.h"
#include "keywrap.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_Status KeyWrap(const uint8_t cek[AES_256_KEY_LEN], const uint8_t kek[AES_256_KEY_LEN],
                   uint8_t cipherText[AES_256_KEY_WRAP_LEN])
{
    mbedtls_nist_kw_context kw;
    size_t n;
    int ret;

    mbedtls_nist_kw_init(&kw);
    ret = mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, kek, AES_256_KEY_LEN * 8, 1);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW, cek, AES_256_KEY_LEN,
                               cipherText, &n, AES_256_KEY_WRAP_LEN);
    if (ret != 0) {
        goto Exit;
    }
    if (n != AES_256_KEY_WRAP_LEN) {
        ret = -1;
        goto Exit;
    }

Exit:
    mbedtls_nist_kw_free(&kw);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status KeyUnwrap(const uint8_t cipherText[AES_256_KEY_WRAP_LEN], const uint8_t kek[AES_256_KEY_LEN],
                     uint8_t cek[AES_256_KEY_LEN])
{
    mbedtls_nist_kw_context kw;
    size_t n;
    int ret;

    mbedtls_nist_kw_init(&kw);
    ret = mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, kek, AES_256_KEY_LEN * 8, 0);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_nist_kw_unwrap(&kw, MBEDTLS_KW_MODE_KW, cipherText, AES_256_KEY_WRAP_LEN,
                                 cek, &n, AES_256_KEY_LEN);
    if (ret != 0) {
        goto Exit;
    }
    if (n != AES_256_KEY_LEN) {
        ret = -1;
        goto Exit;
    }

Exit:
    mbedtls_nist_kw_free(&kw);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
