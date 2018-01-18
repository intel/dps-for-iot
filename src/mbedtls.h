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

#ifndef _MBEDTLS_H
#define _MBEDTLS_H

#include "mbedtls/ecdh.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *TLSErrTxt(int ret);

/*
 * @param curve the elliptic curve ID
 * @param id the mbedtls elliptic curve ID
 * @param len the size of a coordinate, in bytes
 */
int TLSGetCurveParams(DPS_ECCurve curve, mbedtls_ecp_group_id* id, size_t* len);

const mbedtls_x509_name* TLSCertificateCN(const mbedtls_x509_crt* crt);

#ifdef __cplusplus
}
#endif

#endif
