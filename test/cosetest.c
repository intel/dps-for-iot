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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test.h"
#include <dps/dbg.h>
#include <dps/err.h>
#include <dps/private/dps.h>
#include "ccm.h"
#include "cose.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static const uint8_t msg[] = {
   0x82,0x81,0x66,0x61,0x2f,0x62,0x2f,0x63,0x00,0x40
};

static const uint8_t aad[] = {
    0xa5,0x03,0x00,0x04,0x50,0xb8,0x5e,0x9a,0xdd,0xd5,0x55,0x88,0xc4,0x57,0xbd,0x01,
    0x19,0x77,0x71,0xa9,0x2a,0x05,0x01,0x06,0xf4,0x07,0x83,0x01,0x19,0x20,0x00,0x58,
    0x2d,0x00,0xbc,0x0d,0x88,0x02,0x09,0x00,0xd1,0x83,0x0a,0xa0,0x33,0x50,0x07,0x6c,
    0x00,0xc2,0x41,0x0d,0x46,0x00,0x19,0x01,0x39,0x58,0x00,0x5a,0x00,0xf0,0x12,0x6c,
    0x00,0x1f,0x01,0xc6,0x00,0x4a,0x00,0xd6,0x00,0x06,0x81,0x19,0x20,0x3d
};

static const uint8_t nonce[] = {
    0x01,0x00,0x00,0x00,0x38,0x5e,0x9a,0xdd,0xd5,0x55,0x88,0xc4,0x57
};

static const uint8_t key[] = {
    0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10
};

static DPS_UUID keyId = {
    .val= { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 }
};

static void Dump(const char* tag, const uint8_t* data, size_t len)
{
    size_t i;
    printf("%s:", tag);
    for (i = 0; i < len; ++i) {
        if ((i % 16) == 0)  {
            printf("\n");
        }
        printf("%02x", data[i]);
    }
    printf("\n");
}

uint8_t config[] = {
    AES_CCM_16_64_128,
    AES_CCM_16_128_128
};

static DPS_Status GetKey(void* ctx, const DPS_UUID* kid, int8_t alg, uint8_t* k)
{
    if (DPS_UUIDCompare(kid, &keyId) != 0) {
        ASSERT(0);
        return DPS_ERR_MISSING;
    } else {
        memcpy(k, key, sizeof(key));
        return DPS_OK;
    }
}

static void CCM_Raw()
{
    DPS_Status ret;
    DPS_TxBuffer cipherText;
    DPS_TxBuffer plainText;

    DPS_TxBufferInit(&cipherText, NULL, 512);
    DPS_TxBufferInit(&plainText, NULL, 512);

    ret = Encrypt_CCM(key, 16, 2, nonce, (uint8_t*)msg, sizeof(msg), aad, sizeof(aad), &cipherText);
    ASSERT(ret == DPS_OK);
    ret = Decrypt_CCM(key, 16, 2, nonce, cipherText.base, DPS_TxBufferUsed(&cipherText), aad, sizeof(aad), &plainText);
    ASSERT(ret == DPS_OK);

    ASSERT(DPS_TxBufferUsed(&plainText) == sizeof(msg));
    ASSERT(memcmp(plainText.base, msg, sizeof(msg)) == 0);

    DPS_TxBufferFree(&cipherText);
    DPS_TxBufferFree(&plainText);
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    int i;

    DPS_Debug = 1;

    CCM_Raw();

    for (i = 0; i < sizeof(config); ++i) {
        uint8_t alg = config[i];
        DPS_UUID kid;
        DPS_RxBuffer aadBuf;
        DPS_RxBuffer msgBuf;
        DPS_TxBuffer cipherText;
        DPS_TxBuffer plainText;
        DPS_RxBuffer input;

        DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));
        DPS_RxBufferInit(&msgBuf, (uint8_t*)msg, sizeof(msg));

        ret = COSE_Encrypt(alg, &keyId, nonce, &aadBuf, &msgBuf, GetKey, NULL, &cipherText);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
            return EXIT_FAILURE;
        }
        Dump("CipherText", cipherText.base, DPS_TxBufferUsed(&cipherText));
        /*
         * Turn output buffers into input buffers
         */
        DPS_TxBufferToRx(&cipherText, &input);

        DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));

        ret = COSE_Decrypt(nonce, &kid, &aadBuf, &input, GetKey, NULL, &plainText);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("COSE_Decrypt failed: %s\n", DPS_ErrTxt(ret));
            return EXIT_FAILURE;
        }

        ASSERT(DPS_TxBufferUsed(&plainText) == sizeof(msg));
        ASSERT(memcmp(plainText.base, msg, sizeof(msg)) == 0);

        DPS_TxBufferFree(&cipherText);
        DPS_TxBufferFree(&plainText);
    }

    DPS_PRINT("Passed\n");
    return EXIT_SUCCESS;
}
