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
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>

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

DPS_Status Encrypt_CCM(const uint8_t key[AES_128_KEY_LENGTH],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[DPS_CCM_NONCE_SIZE],
                       uint8_t* msg,
                       uint32_t msgLen,
                       const uint8_t* aad,
                       uint32_t aadLen)
{
    int32_t r;
    struct tc_aes_key_sched_struct sched;
    struct tc_ccm_mode_struct ctx;

    tc_aes128_set_encrypt_key(&sched, key);

    r = tc_ccm_config(&ctx, &sched, (uint8_t*)nonce, DPS_CCM_NONCE_SIZE, M);
    if (!r) {
        return DPS_ERR_INVALID;
    }
    r = tc_ccm_generation_encryption(msg, aad, aadLen, msg, msgLen, &ctx);
    if (!r) {
        return DPS_ERR_INVALID;
    }
    SecureZeroMemory(&sched, sizeof(sched));
    return DPS_OK;
}

DPS_Status Decrypt_CCM(const uint8_t key[AES_128_KEY_LENGTH],
                       uint8_t M,
                       uint8_t L,
                       const uint8_t nonce[DPS_CCM_NONCE_SIZE],
                       uint8_t* msg,
                       uint32_t msgLen,
                       const uint8_t* aad,
                       uint32_t aadLen)
{
    int32_t r;
    struct tc_aes_key_sched_struct sched;
    struct tc_ccm_mode_struct ctx;

    tc_aes128_set_encrypt_key(&sched, key);

    r = tc_ccm_config(&ctx, &sched, (uint8_t*)nonce, DPS_CCM_NONCE_SIZE, M);
    if (!r) {
        return DPS_ERR_INVALID;
    }
    r = tc_ccm_decryption_verification(msg, aad, aadLen, msg, msgLen, &ctx);
    if (!r) {
        return DPS_ERR_SECURITY;
    }
    SecureZeroMemory(&sched, sizeof(sched));
    return DPS_OK;
}
