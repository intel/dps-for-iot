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

#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/x509_crt.h"
#include <dps/private/mbedtls.h>
#include <dps/private/crypto.h>
#include <dps/private/ec.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define MAX_CERT_LEN 16000

const char *TLSErrTxt(int ret)
{
    static char errBuf[256] = { 0 };
    mbedtls_strerror(ret, errBuf, sizeof(errBuf));
    return errBuf;
}

int TLSGetCurveParams(DPS_ECCurve curve, mbedtls_ecp_group_id* id, size_t* len)
{
    int ret = 0;

    switch (curve) {
    case DPS_EC_CURVE_P521:
        *id = MBEDTLS_ECP_DP_SECP521R1;
        break;
    case DPS_EC_CURVE_P384:
        *id = MBEDTLS_ECP_DP_SECP384R1;
        break;
    default:
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        break;
    }
    *len = CoordinateSize_EC(curve);
    return ret;
}

#define PERSONALIZATION_STRING "DPS_DRBG"

typedef struct _DPS_RBG {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
} DPS_RBG;

DPS_RBG* DPS_CreateRBG()
{
    DPS_RBG* rbg;
    int ret;

    rbg = malloc(sizeof(DPS_RBG));
    if (!rbg) {
        return NULL;
    }
    mbedtls_entropy_init(&rbg->entropy);
    mbedtls_ctr_drbg_init(&rbg->drbg);
    ret = mbedtls_ctr_drbg_seed(&rbg->drbg, mbedtls_entropy_func, &rbg->entropy,
                                (const unsigned char*)PERSONALIZATION_STRING, sizeof(PERSONALIZATION_STRING) - 1);
    if (ret != 0) {
        DPS_ERRPRINT("Seed RBG failed: %s\n", TLSErrTxt(ret));
        DPS_DestroyRBG(rbg);
        return NULL;
    }
    return rbg;
}

void DPS_DestroyRBG(DPS_RBG* rbg)
{
    if (rbg) {
        mbedtls_ctr_drbg_free(&rbg->drbg);
        mbedtls_entropy_free(&rbg->entropy);
        free(rbg);
    }
}

DPS_Status DPS_RandomKey(DPS_RBG* rbg, uint8_t key[AES_256_KEY_LEN])
{
    int ret;

    if (!rbg) {
        return DPS_ERR_ARGS;
    }
    ret = mbedtls_ctr_drbg_random(&rbg->drbg, key, AES_256_KEY_LEN);
    if (ret != 0) {
        DPS_ERRPRINT("Generate random bytes failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_FAILURE;
    }
    return DPS_OK;
}

DPS_Status DPS_EphemeralKey(DPS_RBG* rbg, DPS_ECCurve curve,
                            uint8_t x[EC_MAX_COORD_LEN], uint8_t y[EC_MAX_COORD_LEN],
                            uint8_t d[EC_MAX_COORD_LEN])
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_group_id id;
    size_t len;
    int ret;

    if (!rbg) {
        return DPS_ERR_ARGS;
    }

    mbedtls_ecp_keypair_init(&keypair);

    ret = TLSGetCurveParams(curve, &id, &len);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_ecp_gen_key(id, &keypair, mbedtls_ctr_drbg_random, &rbg->drbg);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair.Q.X, x, len);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair.Q.Y, y, len);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair.d, d, len);
    if (ret != 0) {
        goto Exit;
    }

Exit:
    mbedtls_ecp_keypair_free(&keypair);
    if (ret == 0) {
        return DPS_OK;
    } else {
        DPS_ERRPRINT("Generate ephemeral key failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_FAILURE;
    }
}

const mbedtls_x509_name* TLSCertificateCN(const mbedtls_x509_crt* crt)
{
    const mbedtls_x509_name *name;

    if (!crt) {
        return NULL;
    }

    for (name = &crt->subject; name; name = name->next) {
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
            return name;
        }
    }
    return NULL;
}

char* DPS_CertificateCN(const char* cert)
{
    mbedtls_x509_crt crt;
    const mbedtls_x509_name *name;
    char* cn = NULL;
    size_t len;
    int ret;

    len = cert ? strnlen(cert, MAX_CERT_LEN) + 1 : 0;
    if (len > MAX_CERT_LEN) {
        DPS_ERRPRINT("Invalid certificate\n");
        return NULL;
    }

    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)cert, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parse certificate failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    name = TLSCertificateCN(&crt);
    if (name) {
        cn = malloc(name->val.len + 1);
        if (!cn) {
            goto Exit;
        }
        memcpy(cn, name->val.p, name->val.len);
        cn[name->val.len] = '\0';
    }
Exit:
    mbedtls_x509_crt_free(&crt);
    return cn;
}

