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
#include "gcm.h"
#include "mbedtls.h"
#include "mbedtls/gcm.h"
#include "mbedtls/error.h"

#define M 16 /* Tag length, in bytes */

DPS_Status Encrypt_GCM(const uint8_t key[AES_256_KEY_LEN],
                       const uint8_t nonce[AES_GCM_NONCE_LEN],
                       DPS_RxBuffer* plainText, size_t numPlainText,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* cipherText)
{
    mbedtls_gcm_context ctx;
    size_t len;
    int ret;
    size_t ptLen;
    size_t i;
    char buf[16];

    ptLen = 0;
    for (i = 0; i < numPlainText; ++i) {
        ptLen += DPS_RxBufferAvail(&plainText[i]);
    }
    if (DPS_TxBufferSpace(cipherText) < (ptLen + M)) {
        return DPS_ERR_OVERFLOW;
    }

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_256_KEY_LEN * 8);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher set key failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, nonce, AES_GCM_NONCE_LEN, aad, aadLen);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher start failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

    for (i = 0; i < numPlainText; ++i) {
        /*
         * Updates must be a multiple of 16 bytes
         */
        len = (DPS_RxBufferAvail(&plainText[i]) / 16) * 16;
        ret = mbedtls_gcm_update(&ctx, len, plainText[i].rxPos, cipherText->txPos);
        if (ret != 0) {
            DPS_ERRPRINT("Cipher update failed: %s\n", TLSErrTxt(ret));
            goto Exit;
        }
        plainText[i].rxPos += len;
        cipherText->txPos += len;

        if (DPS_RxBufferAvail(&plainText[i])) {
            if ((i + 1) < numPlainText) {
                size_t borrow;
                /*
                 * Copy and borrow to make a 16 byte buffer for update
                 */
                len = DPS_RxBufferAvail(&plainText[i]);
                assert(len <= 16);
                memcpy(buf, plainText[i].rxPos, len);
                plainText[i].rxPos += len;

                borrow = DPS_RxBufferAvail(&plainText[i + 1]);
                if (borrow > (16 - len)) {
                    borrow = 16 - len;
                }
                memcpy(&buf[len], plainText[i + 1].rxPos, borrow);
                plainText[i + 1].rxPos += borrow;
                ret = mbedtls_gcm_update(&ctx, len + borrow, (const unsigned char*)buf, cipherText->txPos);
                if (ret != 0) {
                    DPS_ERRPRINT("Cipher update failed: %s\n", TLSErrTxt(ret));
                    goto Exit;
                }
                cipherText->txPos += len + borrow;
            } else {
                /*
                 * Last update can be less than 16 bytes
                 */
                len = DPS_RxBufferAvail(&plainText[i]);
                ret = mbedtls_gcm_update(&ctx, len, plainText[i].rxPos, cipherText->txPos);
                if (ret != 0) {
                    DPS_ERRPRINT("Cipher update failed: %s\n", TLSErrTxt(ret));
                    goto Exit;
                }
                plainText[i].rxPos += len;
                cipherText->txPos += len;
            }
        }
    }

    ret = mbedtls_gcm_finish(&ctx, cipherText->txPos, M);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher finish failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    cipherText->txPos += M;

Exit:
    mbedtls_gcm_free(&ctx);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status Decrypt_GCM(const uint8_t key[AES_256_KEY_LEN],
                       const uint8_t nonce[AES_GCM_NONCE_LEN],
                       const uint8_t* cipherText, size_t ctLen,
                       const uint8_t* aad, size_t aadLen,
                       DPS_TxBuffer* plainText)
{
    const mbedtls_cipher_info_t* info;
    mbedtls_cipher_context_t ctx;
    size_t ptLen = ctLen - M;
    int ret;
    size_t outLen;

    if (DPS_TxBufferSpace(plainText) < ptLen) {
        return DPS_ERR_OVERFLOW;
    }

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
    mbedtls_cipher_init(&ctx);
    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher setup failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_cipher_setkey(&ctx, key, AES_256_KEY_LEN * 8, MBEDTLS_DECRYPT);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher set key failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    outLen = DPS_TxBufferSpace(plainText);
    ret = mbedtls_cipher_auth_decrypt(&ctx, nonce, AES_GCM_NONCE_LEN, aad, aadLen, cipherText, ptLen,
                                      plainText->base, &outLen, cipherText + ptLen, M);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher auth decrypt failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    plainText->txPos += ptLen;

Exit:
    mbedtls_cipher_free(&ctx);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
