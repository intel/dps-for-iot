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
#include <assert.h>
#include <dps/dbg.h>
#include <dps/err.h>
#include <dps/private/dps.h>
#include "cose.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static const char msg[] = "This is the content.";

static const uint8_t nonce[] = { 0x89, 0xF5, 0x2F, 0x65, 0xA1, 0xC5, 0x80, 0x93, 0x3B, 0x52, 0x61, 0xA7, 0x2F };

static const uint8_t aad[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

static const uint8_t key[] = { 0x84, 0x9B, 0x57, 0x21, 0x9D, 0xAE, 0x48, 0xDE, 0x64, 0x6D, 0x07, 0xDB, 0xB5, 0x33, 0x56, 0x6E };

DPS_UUID keyId;

void Dump(const char* tag, const uint8_t* data, size_t len)
{
    size_t i;
    printf("%s: ", tag);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

uint8_t config[] = {
   AES_CCM_16_64_128,
   AES_CCM_16_128_128
};

static DPS_Status GetKey(DPS_UUID* kid, int8_t alg, uint8_t* k)
{
    if (DPS_UUIDCompare(kid, &keyId) != 0) {
        return DPS_ERR_MISSING;
    } else {
        memcpy(k, key, sizeof(key));
        return DPS_OK;
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_Buffer aadBuf;
    DPS_Buffer msgBuf;
    DPS_Buffer output;
    DPS_Buffer input;
    int i;

    for (i = 0; i < 16; ++i) {
        keyId.val[i] = i + 1;
    }

    for (i = 0; i < sizeof(config); ++i) {
        uint8_t alg = config[i];

        DPS_BufferInit(&aadBuf, NULL, sizeof(aad));
        DPS_BufferAppend(&aadBuf, aad, sizeof(aad));

        DPS_BufferInit(&msgBuf, NULL, sizeof(msg));
        DPS_BufferAppend(&msgBuf, msg, sizeof(msg) - 1);

        ret = COSE_Encrypt(alg, &keyId, nonce, &aadBuf, &msgBuf, GetKey, &output);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
            return 1;
        }

        free(msgBuf.base);
        Dump("Cryptext", output.base, DPS_BufferUsed(&output));

        DPS_BufferInit(&input, output.base, DPS_BufferUsed(&output));
        ret = COSE_Decrypt(nonce, &aadBuf, &input, GetKey, &msgBuf);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("COSE_Decrypt failed: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
        free(input.base);
        if (aadBuf.base) {
            free(aadBuf.base);
        }
    }
    
    DPS_PRINT("Passed\n");
    return 0;
}
