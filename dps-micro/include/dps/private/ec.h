/**
 * @file
 * Elliptic curve algorithms
 */

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

#ifndef _EC_H
#define _EC_H

#include <dps/private/dps.h>
#include <dps/private/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum length of the ECDH shared secret, in bytes
 */
#define ECDH_MAX_SHARED_SECRET_LEN 66

/**
 * The @p curve parameter determines the size of the x, y, and d
 * coordinates
 *
 *   Curve | Coordinate Size (bytes)
 *   ----- | -----------------------
 *   P521  | 66
 *   P384  | 48
 *
 * @param curve the elliptic curve ID
 *
 * @return the coordinate size, in bytes
 */
size_t CoordinateSize_EC(DPS_ECCurve curve);

/**
 * Parse the public key from a PEM encoded certificate.
 *
 * @param cert the certificate in PEM format
 * @param curve the elliptic curve ID
 * @param x the X coordinate
 * @param y the Y coordinate
 *
 * @return DPS_OK if parse is successful, an error otherwise
 */
DPS_Status ParseCertificate_ECDSA(const char* cert,
                                  DPS_ECCurve* curve, uint8_t x[EC_MAX_COORD_LEN], uint8_t y[EC_MAX_COORD_LEN]);

/**
 * Parse the private key from a PEM encoded private key.
 *
 * @param privateKey the optional private key in PEM format
 * @param password the optional password protecting the key, may be NULL
 * @param curve the elliptic curve ID
 * @param d the D coordinate
 *
 * @return DPS_OK if parse is successful, an error otherwise
 */
DPS_Status ParsePrivateKey_ECDSA(const char* privateKey, const char* password,
                                 DPS_ECCurve* curve, uint8_t d[EC_MAX_COORD_LEN]);

/**
 * Verify an Elliptic Curve Digital Signature Algorithm signature.
 *
 * The @p curve parameter determines the size of the @p x and @p y
 * coordinates (@see CoordinateSize_EC()), the hashing function used
 * and the expected size of the signature.
 *
 *   Curve | Signature Size (bytes) | Hash
 *   ----- | ---------------------- | ------
 *   P521  | 132                    | SHA512
 *   P384  |  96                    | SHA384
 *
 * Note that the expected signature size is twice the coordinate size:
 * the signature is expected to be the R value concatenated with the S
 * value.
 *
 * @param curve the elliptic curve ID
 * @param x the X coordinate
 * @param y the Y coordinate
 * @param data the data to hash
 * @param dataLen the size of the data, in bytes
 * @param sig the signature to verify
 * @param sigLen the size of the signature, in bytes
 *
 * @return
 *         - DPS_OK if the signature is verified
 *         - DPS_ERR_INVALID if the signature is not verified
 */
DPS_Status Verify_ECDSA(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y,
                        const uint8_t* data, size_t dataLen,
                        const uint8_t* sig, size_t sigLen);

/**
 * Compute an Elliptic Curve Digital Signature Algorithm signature.
 *
 * @see Verify_ECDSA() for a more detailed discussion of the parameters.
 *
 * @param curve the elliptic curve ID
 * @param d the D coordinate
 * @param data the data to hash
 * @param dataLen the size of the data, in bytes
 * @param sig returns the signature
 *
 * @return
 *         - DPS_OK if the signature is computed
 *         - DPS_ERR_INVALID if the signature cannot be computed
 */
DPS_Status Sign_ECDSA(DPS_ECCurve curve, const uint8_t* d,
                      const uint8_t* data, size_t dataLen,
                      DPS_TxBuffer* sig);

/**
 * Computes the Elliptic Curve Diffie-Hellman shared secret.
 *
 * @see CoordinateSize_EC() for a more detailed discussion of the
 * curve parameter.
 *
 * @param curve the elliptic curve ID
 * @param x the sender public key X coordinate
 * @param y the sender public key Y coordinate
 * @param d the recipient private key D coordinate
 * @param secret returns the computed secret
 * @param secretLen returns the size of the computed secret, in bytes
 *
 * @return
 *         - DPS_OK if the secret is computed
 *         - DPS_ERR_INVALID if the secret cannot be computed
 */
DPS_Status ECDH(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y, const uint8_t* d,
                uint8_t secret[ECDH_MAX_SHARED_SECRET_LEN], size_t* secretLen);

#ifdef __cplusplus
}
#endif

#endif
