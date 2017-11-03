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

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <dps/dbg.h>
#include <dps/err.h>
#include "cose.h"
#include <dps/private/cbor.h>
#include "ccm.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#define AES128_KEYLEN      16

#define COSE_MAX_KEYLEN    16
#define COSE_MAX_NONCE_LEN 13

/*
 * These constants are defined in draft-ietf-cose-msg-24
 */
#define COSE_KEY_KTY       1
#define COSE_KEY_KID       2
#define COSE_KEY_ALG       3
#define COSE_KEY_OPS       4
#define COSE_KEY_BASE_IV   5
#define COSE_TAG_ENCRYPT0 16

static const uint8_t ENCRYPT0[] = { 'E', 'n', 'c', 'r', 'y', 'p', 't', '0' };

#ifndef _WIN32
static volatile void* SecureZeroMemory(volatile void* m, size_t l)
{
    volatile uint8_t* p = m;
    while (l--) {
        *p++ = 0;
    }
    return m;
}
#endif

static DPS_Status SetCryptoParams(uint8_t alg, uint8_t* L, uint8_t* M)
{
    switch (alg) {
    case AES_CCM_16_64_128:
        *L = 16 / 8;
        *M = 64 / 8;
        break;
    case AES_CCM_16_128_128:
        *L = 16 / 8;
        *M = 128 / 8;
        break;
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
    return DPS_OK;
}

/*
 * Headroom to allow for various CBOR headers
 */
#define HEADROOM  32

static DPS_Status EncodeUnprotectedMap(DPS_TxBuffer* buf, const DPS_UUID* kid)
{
    DPS_Status ret;
    /*
     * { 5:nonce }
     */
    ret = CBOR_EncodeMap(buf, 1);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, COSE_KEY_KID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, (uint8_t*)kid, sizeof(DPS_UUID));
    }
    return ret;
}

static DPS_Status EncodeProtectedMap(DPS_TxBuffer* buf, uint8_t alg)
{
    uint8_t* wrapPtr;
    DPS_Status ret;

    /*
     * Map is wrapped in a bytstream
     */
    ret = CBOR_StartWrapBytes(buf, 3, &wrapPtr);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(buf, 1);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, COSE_KEY_KTY);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, alg);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EndWrapBytes(buf, wrapPtr);
    }
    return ret;
}

static DPS_Status EncodeAAD(uint8_t alg, DPS_TxBuffer* buf, uint8_t* aad, size_t aadLen)
{
    DPS_Status ret;
    size_t bufSize = sizeof(ENCRYPT0) + aadLen + HEADROOM;

    ret = DPS_TxBufferInit(buf, NULL, bufSize);
    if (ret == DPS_OK) {
        /*
         * [ context: "Encrypt0", protected: map external-aad: bstr ]
         */
        ret = CBOR_EncodeArray(buf, 3);
    }
    if (ret == DPS_OK) {
        /*
         * COSE spec does not expect a trailing NUL
         */
        ret = CBOR_EncodeLength(buf, sizeof(ENCRYPT0), CBOR_STRING);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buf, ENCRYPT0, sizeof(ENCRYPT0));
    }
    if (ret == DPS_OK) {
        /*
         * { 1:algorithm }
         */
        ret = EncodeProtectedMap(buf, alg);
    }
    if (ret == DPS_OK) {
        /*
         * external aad
         */
        ret = CBOR_EncodeBytes(buf, aad, aadLen);
    }
    return ret;
}

DPS_Status COSE_Encrypt(int8_t alg,
                        const DPS_UUID* kid,
                        const uint8_t nonce[DPS_COSE_NONCE_SIZE],
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* plainText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        DPS_TxBuffer* cipherText)
{
    DPS_Status ret;
    DPS_TxBuffer AAD;
    uint8_t key[AES_128_KEY_LENGTH];
    uint8_t L;
    uint8_t M;
    size_t ptLen;
    size_t aadLen;
    size_t ctLen;

    DPS_DBGTRACE();

    DPS_TxBufferClear(cipherText);
    DPS_TxBufferClear(&AAD);

    if (!aad || !plainText || !keyCB || !cipherText || !kid) {
        return DPS_ERR_NULL;
    }
    ret = SetCryptoParams(alg, &L, &M);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    ret = keyCB(ctx, kid, alg, key);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Encode the canonical AAD
     */
    ret = EncodeAAD(alg, &AAD, aad->base, DPS_RxBufferAvail(aad));
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    aadLen = DPS_TxBufferUsed(&AAD);
    ptLen = DPS_RxBufferAvail(plainText);
    /*
     * Allocate cipherText buffer and copy in headers
     */
    ctLen = aadLen - DPS_RxBufferAvail(aad) + ptLen + M + sizeof(kid) + HEADROOM;
    ret = DPS_TxBufferInit(cipherText, NULL, ctLen);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Prefix with the COSE tag
     */
    ret = CBOR_EncodeTag(cipherText, COSE_TAG_ENCRYPT0);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Output is a CBOR array of 3 elements
     */
    ret = CBOR_EncodeArray(cipherText, 3);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * [1] Protected headers
     */
    ret = EncodeProtectedMap(cipherText, alg);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * [2] Unprotected map
     */
    ret = EncodeUnprotectedMap(cipherText, kid);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * [3] Cryptext byte string
     */
    ret = CBOR_EncodeLength(cipherText, ptLen + M, CBOR_BYTES);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    ret = Encrypt_CCM(key, M, L, nonce, plainText->base, ptLen, AAD.base, aadLen, cipherText);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    SecureZeroMemory(key, sizeof(key));
    /*
     * Don't need AAD anymore
     */
    DPS_TxBufferFree(&AAD);

    return DPS_OK;

ErrorExit:

    SecureZeroMemory(key, sizeof(key));
    DPS_TxBufferFree(cipherText);
    DPS_TxBufferFree(&AAD);
    return ret;
}

static DPS_Status DecodeUnprotectedMap(DPS_RxBuffer* buf, DPS_UUID* kid)
{
    DPS_Status ret;
    size_t size;

    ret = CBOR_DecodeMap(buf, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    while (size--) {
        int8_t key;
        uint8_t* data;
        size_t len;

        ret = CBOR_DecodeInt8(buf, &key);
        if (ret != DPS_OK) {
            return ret;
        }
        if (key != COSE_KEY_KID) {
            return DPS_ERR_INVALID;
        }
        ret = CBOR_DecodeBytes(buf, &data, &len);
        if (ret != DPS_OK) {
            return ret;
        }
        if (len != sizeof(DPS_UUID)) {
            return DPS_ERR_INVALID;
        }
        memcpy(kid, data, sizeof(DPS_UUID));
    }
    return ret;
}

/*
 * Decode the protected headers
 */
static DPS_Status DecodeProtectedMap(DPS_RxBuffer* buf, int8_t* alg)
{
    DPS_Status ret;
    size_t size;
    int64_t key;
    uint8_t* map;
    DPS_RxBuffer mapBuf;

    /*
     * Protected map is wrapped inside a byte string
     */
    ret = CBOR_DecodeBytes(buf, &map, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * Decode from the bytestring
     */
    DPS_RxBufferInit(&mapBuf, map, size);
    ret = CBOR_DecodeMap(&mapBuf, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    /*
     * For now we only expect 1 entry
     */
    if (size != 1) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeInt(&mapBuf, &key);
    if (ret != DPS_OK) {
        return ret;
    }
    if (key == COSE_KEY_KTY) {
        ret = CBOR_DecodeInt8(&mapBuf, alg);
    } else {
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

DPS_Status COSE_Decrypt(const uint8_t nonce[DPS_COSE_NONCE_SIZE],
                        DPS_UUID* kid,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* cipherText,
                        COSE_KeyRequest keyCB,
                        void* ctx,
                        DPS_TxBuffer* plainText)
{
    DPS_Status ret;
    DPS_TxBuffer AAD;
    uint8_t key[AES_128_KEY_LENGTH];
    uint8_t L;
    uint8_t M;
    size_t sz;
    int8_t alg;
    uint64_t tag;
    size_t aadLen;
    size_t ctLen;
    uint8_t* cryptText;

    DPS_DBGTRACE();

    DPS_TxBufferClear(plainText);
    DPS_TxBufferClear(&AAD);

    if (!aad || !cipherText || !keyCB || !plainText || !kid) {
        return DPS_ERR_NULL;
    }
    /*
     * Check this is a COSE payload
     */
    ret = CBOR_DecodeTag(cipherText, &tag);
    if ((ret != DPS_OK) || (tag != COSE_TAG_ENCRYPT0)) {
        return DPS_ERR_NOT_ENCRYPTED;
    }
    /*
     * Input is a CBOR array of 3 elements
     */
    ret = CBOR_DecodeArray(cipherText, &sz);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    if (sz != 3) {
        ret = DPS_ERR_INVALID;
        goto ErrorExit;
    }
    /*
     * [1] Protected headers
     */
    ret = DecodeProtectedMap(cipherText, &alg);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    ret = SetCryptoParams(alg, &L, &M);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * [2] Unprotected map
     */
    ret = DecodeUnprotectedMap(cipherText, kid);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    ret = keyCB(ctx, kid, alg, key);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * [3] Encrypted byte string
     */
    ret = CBOR_DecodeBytes(cipherText, &cryptText, &ctLen);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Buffer to return the decrypted plain text
     */
    ret = DPS_TxBufferInit(plainText, NULL, ctLen - M);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Encode the cannonical AAD
     */
    ret = EncodeAAD(alg, &AAD, aad->base, DPS_RxBufferAvail(aad));
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    aadLen = DPS_TxBufferUsed(&AAD);
    ret = Decrypt_CCM(key, M, L, nonce, cryptText, ctLen, AAD.base, aadLen, plainText);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    SecureZeroMemory(key, sizeof(key));
    DPS_TxBufferFree(&AAD);

    return DPS_OK;

ErrorExit:

    SecureZeroMemory(key, sizeof(key));
    DPS_TxBufferFree(&AAD);
    DPS_TxBufferFree(plainText);
    return ret;
}
