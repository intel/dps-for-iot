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
#include <mbedtls/aes.h>
#include <dps/private/keywrap.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * The default IV defined in RFC 3394.
 */
static const uint64_t IV = 0xa6a6a6a6a6a6a6a6;

DPS_Status KeyWrap(const uint8_t cek[AES_256_KEY_LEN], const uint8_t kek[AES_256_KEY_LEN],
                   uint8_t cipherText[AES_256_KEY_WRAP_LEN])
{
    DPS_Status status = DPS_ERR_INVALID;
    mbedtls_aes_context aes;
    uint8_t A[AES_256_KEY_LEN];
    uint8_t* R;
    size_t i, j, t, Rlen;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, kek, AES_256_KEY_LEN * 8);
    if (ret != 0) {
        goto Exit;
    }

    if (sizeof(IV) > sizeof(A)) {
        goto Exit;
    }
    memcpy(A, &IV, sizeof(IV));
    if (AES_256_KEY_LEN > (AES_256_KEY_WRAP_LEN - 8)) {
        goto Exit;
    }
    memcpy(cipherText + 8, cek, AES_256_KEY_LEN);
    t = 1;
    for (j = 0; j < 6; ++j) {
        R = cipherText + 8;
        Rlen = AES_256_KEY_WRAP_LEN - 8;
        for (i = 0; i < (AES_256_KEY_LEN / 8); ++i, ++t, R += 8, Rlen -= 8) {
            memcpy(A + 8, R, 8);
            ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, A, A);
            if (ret != 0) {
                goto Exit;
            }
            memcpy(A, A, 8);
            A[4] ^= (t >> 24) & 0xff;
            A[5] ^= (t >> 16) & 0xff;
            A[6] ^= (t >>  8) & 0xff;
            A[7] ^= (t >>  0) & 0xff;
            memcpy(R, A + 8, 8);
        }
    }
    memcpy(cipherText, A, 8);
    status = DPS_OK;

Exit:
    mbedtls_aes_free(&aes);
    return status;
}

DPS_Status KeyUnwrap(const uint8_t cipherText[AES_256_KEY_WRAP_LEN], const uint8_t kek[AES_256_KEY_LEN],
                     uint8_t cek[AES_256_KEY_LEN])
{
    mbedtls_aes_context aes;
    uint8_t A[AES_256_KEY_LEN];
    uint8_t* R;
    size_t i, j, t, Rlen;
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_dec(&aes, kek, AES_256_KEY_LEN * 8);
    if (ret != 0) {
        goto Exit;
    }

    memcpy(A, cipherText, 8);
    memcpy(cek, cipherText + 8, AES_256_KEY_LEN);
    t = (AES_256_KEY_LEN / 8) * 6;
    for (j = 6; j > 0; --j) {
        R = cek + AES_256_KEY_LEN - 8;
        Rlen = 8;
        for (i = (AES_256_KEY_LEN / 8); i > 0; --i, --t, R -= 8, Rlen += 8) {
            A[4] ^= (t >> 24) & 0xff;
            A[5] ^= (t >> 16) & 0xff;
            A[6] ^= (t >>  8) & 0xff;
            A[7] ^= (t >>  0) & 0xff;
            memcpy(A + 8, R, 8);
            ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, A, A);
            if (ret != 0) {
                goto Exit;
            }
            memcpy(R, A + 8, 8);
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
