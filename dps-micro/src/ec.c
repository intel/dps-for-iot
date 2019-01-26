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
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <dps/private/ec.h>
#include <dps/private/mbedtls.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

size_t CoordinateSize_EC(DPS_ECCurve curve)
{
    switch (curve) {
    case DPS_EC_CURVE_P521:
        return 66;
    case DPS_EC_CURVE_P384:
        return 48;
    default:
        return 0;
    }
}

static int GetGroupParams(const mbedtls_ecp_group* group, DPS_ECCurve* curve, size_t* len)
{
    int ret = 0;

    switch (group->id) {
    case MBEDTLS_ECP_DP_SECP521R1:
        *curve = DPS_EC_CURVE_P521;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        *curve = DPS_EC_CURVE_P384;
        break;
    default:
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        DPS_ERRPRINT("Unsupported group: %s\n", TLSErrTxt(ret));
        break;
    }
    *len = (group->nbits + 7) / 8;
    return ret;
}

/*
 * @param curve the elliptic curve ID
 * @param md the hash function to use for ECDSA
 */
static int GetHashFunction(DPS_ECCurve curve, mbedtls_md_type_t* md)
{
    int ret = 0;

    switch (curve) {
    case DPS_EC_CURVE_P521:
        *md = MBEDTLS_MD_SHA512;
        break;
    case DPS_EC_CURVE_P384:
        *md = MBEDTLS_MD_SHA384;
        break;
    default:
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        DPS_ERRPRINT("Unsupported hash function: %s\n", TLSErrTxt(ret));
        break;
    }
    return ret;
}

/*
 * @param keypair the keypair to set; must be initialized before calling this function
 * @param id the curve
 * @param len the size of the coordinates, in bytes
 * @param x may be NULL if a private key
 * @param y may be NULL if a private key
 * @param d may be NULL if a public key
 *
 * @return 0 on success
 */
static int SetKeypair(mbedtls_ecp_keypair* keypair, mbedtls_ecp_group_id id, size_t len,
                      const uint8_t* x, const uint8_t* y, const uint8_t* d)
{
    int ret;

    ret = mbedtls_ecp_group_load(&keypair->grp, id);
    if (ret != 0) {
        DPS_ERRPRINT("ECP group load failed: %s\n", TLSErrTxt(ret));
        return ret;
    }
    if (x && y) {
        ret = mbedtls_mpi_read_binary(&keypair->Q.X, x, len);
        if (ret != 0) {
            DPS_ERRPRINT("MPI read binary failed: %s\n", TLSErrTxt(ret));
            return ret;
        }
        ret = mbedtls_mpi_read_binary(&keypair->Q.Y, y, len);
        if (ret != 0) {
            DPS_ERRPRINT("MPI read binary failed: %s\n", TLSErrTxt(ret));
            return ret;
        }
        ret = mbedtls_mpi_lset(&keypair->Q.Z, 1);
        if (ret != 0) {
            DPS_ERRPRINT("MPI set failed: %s\n", TLSErrTxt(ret));
            return ret;
        }
    }
    if (d) {
        ret = mbedtls_mpi_read_binary(&keypair->d, d, len);
        if (ret != 0) {
            DPS_ERRPRINT("MPI read binary failed: %s\n", TLSErrTxt(ret));
            return ret;
        }
    }
    return ret;
}

DPS_Status Verify_ECDSA(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y,
                        const uint8_t* data, size_t dataLen,
                        const uint8_t* sig, size_t sigLen)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_id id;
    size_t len;
    mbedtls_md_type_t hash;
    const mbedtls_md_info_t* md;
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    int ret;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = TLSGetCurveParams(curve, &id, &len);
    if (ret != 0) {
        DPS_ERRPRINT("Get curve size failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = SetKeypair(&keypair, id, len, x, y, NULL);
    if (ret != 0) {
        goto Exit;
    }
    if (sigLen < (len * 2)) {
        DPS_ERRPRINT("Invalid signature size\n");
        ret = -1;
        goto Exit;
    }

    ret = GetHashFunction(curve, &hash);
    if (ret != 0) {
        DPS_ERRPRINT("Get hash function failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    md = mbedtls_md_info_from_type(hash);
    if (!md) {
        DPS_ERRPRINT("Unsupported hash function\n");
        ret = -1;
        goto Exit;
    }
    mbedtls_md(md, data, dataLen, digest);

    ret = mbedtls_mpi_read_binary(&r, sig, len);
    if (ret != 0) {
        DPS_ERRPRINT("MPI read binary failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_mpi_read_binary(&s, sig + len, len);
    if (ret != 0) {
        DPS_ERRPRINT("MPI read binary failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

    ret = mbedtls_ecdsa_verify(&keypair.grp, digest, mbedtls_md_get_size(md), &keypair.Q, &r, &s);
    if (ret != 0) {
        DPS_ERRPRINT("ECDSA verify signature failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

Exit:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&keypair);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status Sign_ECDSA(DPS_ECCurve curve, const uint8_t* d,
                      const uint8_t* data, size_t dataLen,
                      DPS_TxBuffer* sig)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_mpi r,  s;
    mbedtls_ecp_group_id id;
    size_t len;
    mbedtls_md_type_t hash;
    const mbedtls_md_info_t* md;
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    int ret;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = TLSGetCurveParams(curve, &id, &len);
    if (ret != 0) {
        DPS_ERRPRINT("Get curve size failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = SetKeypair(&keypair, id, len, NULL, NULL, d);
    if (ret != 0) {
        goto Exit;
    }
    if (DPS_TxBufferSpace(sig) < (len * 2)) {
        DPS_ERRPRINT("Insufficient space for signature\n");
        ret = -1;
        goto Exit;
    }

    ret = GetHashFunction(curve, &hash);
    if (ret != 0) {
        DPS_ERRPRINT("Get hash function failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    md = mbedtls_md_info_from_type(hash);
    if (!md) {
        DPS_ERRPRINT("Unsupported hash function\n");
        ret = -1;
        goto Exit;
    }
    mbedtls_md(md, data, dataLen, digest);

    ret = mbedtls_ecdsa_sign_det(&keypair.grp, &r, &s, &keypair.d, digest, mbedtls_md_get_size(md), hash);
    if (ret != 0) {
        DPS_ERRPRINT("ECDSA sign failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

    ret = mbedtls_mpi_write_binary(&r, sig->txPos, len);
    if (ret != 0) {
        DPS_ERRPRINT("Write signature failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    sig->txPos += len;
    ret = mbedtls_mpi_write_binary(&s, sig->txPos, len);
    if (ret != 0) {
        DPS_ERRPRINT("Write signature failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    sig->txPos += len;

Exit:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&keypair);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status ECDH(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y, const uint8_t* d,
                uint8_t secret[ECDH_MAX_SHARED_SECRET_LEN], size_t* secretLen)
{
    mbedtls_ecp_keypair sender;
    mbedtls_ecp_keypair recipient;
    mbedtls_ecdh_context ecdh;
    mbedtls_mpi sec;
    mbedtls_ecp_group_id id;
    size_t len;
    int ret;

    mbedtls_ecp_keypair_init(&sender);
    mbedtls_ecp_keypair_init(&recipient);
    mbedtls_ecdh_init(&ecdh);
    mbedtls_mpi_init(&sec);

    ret = TLSGetCurveParams(curve, &id, &len);
    if (ret != 0) {
        DPS_ERRPRINT("Get curve size failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = SetKeypair(&sender, id, len, x, y, NULL);
    if (ret != 0) {
        goto Exit;
    }
    ret = SetKeypair(&recipient, id, len, NULL, NULL, d);
    if (ret != 0) {
        goto Exit;
    }

    ret = mbedtls_ecdh_compute_shared(&sender.grp, &sec, &sender.Q, &recipient.d, NULL, NULL);
    if (ret != 0) {
        DPS_ERRPRINT("ECDH compute shared secret failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    *secretLen = len;
    ret = mbedtls_mpi_write_binary(&sec, secret, *secretLen);
    if (ret != 0) {
        DPS_ERRPRINT("Write bignum failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

Exit:
    mbedtls_ecp_keypair_free(&sender);
    mbedtls_ecp_keypair_free(&recipient);
    mbedtls_ecdh_free(&ecdh);
    mbedtls_mpi_free(&sec);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status ParseCertificate_ECDSA(const char* cert,
                                  DPS_ECCurve* curve, uint8_t x[EC_MAX_COORD_LEN], uint8_t y[EC_MAX_COORD_LEN])
{
    mbedtls_x509_crt crt;
    mbedtls_ecp_keypair* keypair;
    size_t len;
    int ret;

    len = cert ? strnlen(cert, DPS_MAX_CERT_LEN) + 1 : 0;
    if (len > DPS_MAX_CERT_LEN) {
        DPS_ERRPRINT("Invalid certificate\n");
        return DPS_ERR_ARGS;
    }

    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)cert, len);
    if (ret != 0) {
        DPS_ERRPRINT("X.509 parse failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    if (!mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_ECDSA)) {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        DPS_ERRPRINT("X.509 parse failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    keypair = mbedtls_pk_ec(crt.pk);

    ret = GetGroupParams(&keypair->grp, curve, &len);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair->Q.X, x, len);
    if (ret != 0) {
        DPS_ERRPRINT("Write bignum failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair->Q.Y, y, len);
    if (ret != 0) {
        DPS_ERRPRINT("Write bignum failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

Exit:
    mbedtls_x509_crt_free(&crt);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}

DPS_Status ParsePrivateKey_ECDSA(const char* privateKey, const char* password,
                                 DPS_ECCurve* curve, uint8_t d[EC_MAX_COORD_LEN])
{
    mbedtls_pk_context pk;
    mbedtls_ecp_keypair* keypair;
    size_t len;
    size_t pwLen;
    int ret;

    if (!privateKey) {
        DPS_ERRPRINT("Invalid private key\n");
        return DPS_ERR_ARGS;
    }
    len = strnlen(privateKey, DPS_MAX_PK_LEN + 1);
    if (len > DPS_MAX_PK_LEN) {
        DPS_ERRPRINT("Invalid private key\n");
        return DPS_ERR_ARGS;
    }
    pwLen = strnlen(password, DPS_MAX_PWD_LEN + 1);
    if (pwLen > DPS_MAX_PWD_LEN) {
        DPS_ERRPRINT("Invalid password\n");
        return DPS_ERR_ARGS;
    }

    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)privateKey, len + 1,
                               (const unsigned char*)password, pwLen);
    if (ret != 0) {
        DPS_ERRPRINT("Parse private key failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto Exit;
    }
    keypair = mbedtls_pk_ec(pk);

    ret = GetGroupParams(&keypair->grp, curve, &len);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_mpi_write_binary(&keypair->d, d, len);
    if (ret != 0) {
        DPS_ERRPRINT("Write bignum failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }

Exit:
    mbedtls_pk_free(&pk);
    if (ret == 0) {
        return DPS_OK;
    } else {
        return DPS_ERR_INVALID;
    }
}
