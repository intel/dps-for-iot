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
#include "mbedtls/aes.h"
#include "keywrap.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static const uint64_t IV = 0xa6a6a6a6a6a6a6a6;

DPS_Status KeyWrap(const uint8_t cek[AES_128_KEY_LEN], const uint8_t kek[AES_128_KEY_LEN],
                   uint8_t cipherText[AES_128_KEY_WRAP_LEN])
{
    mbedtls_aes_context aes;
    uint8_t A[AES_128_KEY_LEN];
    uint8_t* R;
    size_t i, j, t, Rlen;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, kek, AES_128_KEY_LEN * 8);
    if (ret != 0) {
        goto Exit;
    }

    memcpy_s(A, sizeof(A), &IV, sizeof(IV));
    memcpy_s(cipherText + 8, AES_128_KEY_WRAP_LEN - 8, cek, AES_128_KEY_LEN);
    t = 1;
    for (j = 0; j < 6; ++j) {
        R = cipherText + 8;
        Rlen = AES_128_KEY_WRAP_LEN - 8;
        for (i = 0; i < (AES_128_KEY_LEN / 8); ++i, ++t, R += 8, Rlen -= 8) {
            memcpy_s(A + 8, sizeof(A) - 8, R, 8);
            mbedtls_aes_encrypt(&aes, A, A);
            memcpy_s(A, sizeof(A), A, 8);
            A[4] ^= (t >> 24) & 0xff;
            A[5] ^= (t >> 16) & 0xff;
            A[6] ^= (t >>  8) & 0xff;
            A[7] ^= (t >>  0) & 0xff;
            memcpy_s(R, Rlen, A + 8, 8);
        }
    }
    memcpy_s(cipherText, AES_128_KEY_WRAP_LEN, A, 8);

Exit:
    mbedtls_aes_free(&aes);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status KeyUnwrap(const uint8_t cipherText[AES_128_KEY_WRAP_LEN], const uint8_t kek[AES_128_KEY_LEN],
                     uint8_t cek[AES_128_KEY_LEN])
{
    mbedtls_aes_context aes;
    uint8_t A[AES_128_KEY_LEN];
    uint8_t* R;
    size_t i, j, t, Rlen;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_dec(&aes, kek, AES_128_KEY_LEN * 8);
    if (ret != 0) {
        goto Exit;
    }

    memcpy_s(A, sizeof(A), cipherText, 8);
    memcpy_s(cek, AES_128_KEY_LEN, cipherText + 8, AES_128_KEY_LEN);
    t = (AES_128_KEY_LEN / 8) * 6;
    for (j = 6; j > 0; --j) {
        R = cek + 8;
        Rlen = AES_128_KEY_LEN - 8;
        for (i = (AES_128_KEY_LEN / 8); i > 0; --i, --t, R -= 8, Rlen += 8) {
            A[4] ^= (t >> 24) & 0xff;
            A[5] ^= (t >> 16) & 0xff;
            A[6] ^= (t >>  8) & 0xff;
            A[7] ^= (t >>  0) & 0xff;
            memcpy_s(A + 8, sizeof(A) - 8, R, 8);
            mbedtls_aes_decrypt(&aes, A, A);
            memcpy_s(R, Rlen, A + 8, 8);
        }
    }
    ret = memcmp(A, &IV, sizeof(IV));

Exit:
    mbedtls_aes_free(&aes);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
