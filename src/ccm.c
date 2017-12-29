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

#include <string.h>
#include <memory.h>
#include "ccm.h"
#include "mbedtls.h"
#include "mbedtls/cipher.h"
#include "mbedtls/error.h"

DPS_Status Encrypt_CCM(const uint8_t key[AES_128_KEY_LEN],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[AES_CCM_NONCE_LEN],
                       const uint8_t* plainText,
                       size_t ptLen,
                       const uint8_t* aad,
                       size_t aadLen,
                       DPS_TxBuffer* cipherText)
{
    const mbedtls_cipher_info_t* info;
    mbedtls_cipher_context_t ctx;
    int ret;
    size_t outLen;

    if (DPS_TxBufferSpace(cipherText) < (ptLen + M)) {
        return DPS_ERR_OVERFLOW;
    }

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CCM);
    mbedtls_cipher_init(&ctx);
    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher setup failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_cipher_setkey(&ctx, key, AES_128_KEY_LEN * 8, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher set key failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    outLen = DPS_TxBufferSpace(cipherText) - M;
    ret = mbedtls_cipher_auth_encrypt(&ctx, nonce, AES_CCM_NONCE_LEN, aad, aadLen, plainText, ptLen,
                                      cipherText->txPos, &outLen, cipherText->txPos + ptLen, M);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher auth encrypt failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    cipherText->txPos += ptLen + M;

Exit:
    mbedtls_cipher_free(&ctx);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status Decrypt_CCM(const uint8_t key[AES_128_KEY_LEN],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[AES_CCM_NONCE_LEN],
                       const uint8_t* cipherText,
                       size_t ctLen,
                       const uint8_t* aad,
                       size_t aadLen,
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

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CCM);
    mbedtls_cipher_init(&ctx);
    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher setup failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_cipher_setkey(&ctx, key, AES_128_KEY_LEN * 8, MBEDTLS_DECRYPT);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher set key failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    outLen = DPS_TxBufferSpace(plainText);
    ret = mbedtls_cipher_auth_decrypt(&ctx, nonce, AES_CCM_NONCE_LEN, aad, aadLen, cipherText, ptLen,
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
