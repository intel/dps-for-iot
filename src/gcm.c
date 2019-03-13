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

static size_t BorrowBytes(uint8_t* dst, DPS_TxBuffer* buf, DPS_TxBuffer* end, uint8_t* src)
{
    size_t n;
    size_t len;

    len = 0;
    for (;;) {
        while ((len < 16) && (src < buf->txPos)) {
            n = buf->txPos - src;
            if (n > (16 - len)) {
                n = 16 - len;
            }
            memcpy(dst, src, n);
            dst += n;
            src += n;
            len += n;
        }
        if ((len == 16) || (++buf == end)) {
            break;
        }
        src = buf->base;
    }
    return len;
}

static void ReturnBytes(uint8_t** dst, DPS_TxBuffer** buf, DPS_TxBuffer* end, uint8_t* src, size_t len)
{
    size_t n;

    for (;;) {
        while (len && ((*dst) < (*buf)->txPos)) {
            n = (*buf)->txPos - (*dst);
            if (n > len) {
                n = len;
            }
            memcpy((*dst), src, n);
            (*dst) += n;
            src += n;
            len -= n;
        }
        if (((*dst) == (*buf)->txPos) && (++(*buf) != end)) {
            (*dst) = (*buf)->base;
        }
        if (!len || ((*buf) == end)) {
            break;
        }
    }
}

DPS_Status Encrypt_GCM(const uint8_t key[AES_256_KEY_LEN],
                       const uint8_t nonce[AES_GCM_NONCE_LEN],
                       DPS_TxBuffer* bufs, size_t numBufs,
                       DPS_TxBuffer* tag,
                       const uint8_t* aad,
                       size_t aadLen)
{
    mbedtls_gcm_context ctx;
    size_t len;
    int ret;
    uint8_t* pos;
    uint8_t tmp[16];

    if (DPS_TxBufferSpace(tag) < M) {
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

    if (numBufs) {
        DPS_TxBuffer* buf = &bufs[0];
        pos = buf->base;
        while (buf < &bufs[numBufs]) {
            /*
             * Updates must be a multiple of 16 bytes
             */
            len = ((buf->txPos - pos) / 16) * 16;
            ret = mbedtls_gcm_update(&ctx, len, pos, pos);
            if (ret != 0) {
                DPS_ERRPRINT("Cipher update failed: %s\n", TLSErrTxt(ret));
                goto Exit;
            }
            pos += len;
            if (pos < buf->txPos) {
                /*
                 * Copy and borrow to make a 16 byte buffer for update,
                 * then copy encrypted data back into place
                 */
                len = BorrowBytes(tmp, buf, &bufs[numBufs], pos);
                ret = mbedtls_gcm_update(&ctx, len, tmp, tmp);
                if (ret != 0) {
                    DPS_ERRPRINT("Cipher update failed: %s\n", TLSErrTxt(ret));
                    goto Exit;
                }
                ReturnBytes(&pos, &buf, &bufs[numBufs], tmp, len);
            } else {
                ++buf;
                pos = buf->base;
            }
        }
    }

    ret = mbedtls_gcm_finish(&ctx, tag->txPos, M);
    if (ret != 0) {
        DPS_ERRPRINT("Cipher finish failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    tag->txPos += M;

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
