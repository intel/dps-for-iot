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
#include <stdlib.h>
#include <assert.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/err.h>
#include <dps/private/cose.h>
#include <dps/private/cbor.h>
#include <dps/private/gcm.h>
#include <dps/private/ec.h>
#include <dps/private/gcm.h>
#include <dps/private/hkdf.h>
#include <dps/private/keywrap.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Define maximum sizes to be used when allocating storage for messages
 */

#define A256KW_LEN 40

#define SIZEOF_PROTECTED_MAP CBOR_SIZEOF_BYTES(CBOR_SIZEOF_MAP(1) +      \
    /* alg */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF(int8_t))

#define SIZEOF_SIGNATURE 132 /* See comments in Verify_ECDSA() for explanation */

#define SIZEOF_COUNTER_SIGNATURE(kidLen) CBOR_SIZEOF_ARRAY(3) +         \
    SIZEOF_PROTECTED_MAP +                                              \
    CBOR_SIZEOF_MAP(1) + /* kid */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF_BYTES(kidLen) + \
    CBOR_SIZEOF_BYTES(SIZEOF_SIGNATURE)

#define SIZEOF_EPHEMERAL_KEY CBOR_SIZEOF_MAP(4) +                       \
    /* kty */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF(int8_t) +               \
    /* crv */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF(int8_t) +               \
    /* x */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF_BYTES(EC_MAX_COORD_LEN) + \
    /* y */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF_BYTES(EC_MAX_COORD_LEN)

#define SIZEOF_RECIPIENT(kidLen) CBOR_SIZEOF_ARRAY(3) +                 \
    SIZEOF_PROTECTED_MAP +                                              \
    CBOR_SIZEOF_MAP(2) +                                                \
    /* alg */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF(int8_t) +               \
    /* ephemeral key */ CBOR_SIZEOF(int8_t) + SIZEOF_EPHEMERAL_KEY +    \
    /* kid */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF_BYTES(kidLen) +         \
    /* content */ CBOR_SIZEOF_BYTES(A256KW_LEN)

#define SIZEOF_PARTY_INFO CBOR_SIZEOF_ARRAY(3) +        \
    /* null */ 1 +                                      \
    /* null */ 1 +                                      \
    /* null */ 1

/*
 * These constants are defined in RFC 8152
 */
#define COSE_HDR_ALG               1
#define COSE_HDR_CRIT              2
#define COSE_HDR_CONTENT_TYPE      3
#define COSE_HDR_KID               4
#define COSE_HDR_IV                5
#define COSE_HDR_PARTIAL_IV        6
#define COSE_HDR_COUNTER_SIGNATURE 7
#define COSE_HDR_EPHEMERAL_KEY     -1

#define COSE_TAG_ENCRYPT0 16
#define COSE_TAG_ENCRYPT  96

#define COSE_KEY_KTY     1
#define COSE_KEY_KID     2
#define COSE_KEY_ALG     3
#define COSE_KEY_KEY_OPS 4
#define COSE_KEY_BASE_IV 5

#define COSE_KEY_KTY_RESERVED  0
#define COSE_KEY_KTY_OKP       1
#define COSE_KEY_KTY_EC        2
#define COSE_KEY_KTY_RSA       3
#define COSE_KEY_KTY_SYMMETRIC 4

#define COSE_EC_KEY_CRV -1
#define COSE_EC_KEY_X   -2
#define COSE_EC_KEY_Y   -3
#define COSE_EC_KEY_D   -4

static const char ENCRYPT0[] = "Encrypt0";
static const char ENCRYPT[] = "Encrypt";
static const char COUNTER_SIGNATURE[] = "CounterSignature";

/*
 * Union of supported key types.
 */
typedef struct _COSE_Key {
    enum {
        COSE_KEY_SYMMETRIC,
        COSE_KEY_EC
    } type; /**< Type of key */
    union {
        struct {
            uint8_t key[AES_256_KEY_LEN];   /**< Key data */
        } symmetric; /**< Symmetric key */
        struct {
            DPS_ECCurve curve; /**< EC curve */
            uint8_t x[EC_MAX_COORD_LEN]; /**< X coordinate */
            uint8_t y[EC_MAX_COORD_LEN]; /**< Y coordinate */
            uint8_t d[EC_MAX_COORD_LEN]; /**< D coordinate */
        } ec; /**< Elliptic curve key */
    };
} COSE_Key;

/*
 * COSE_Signature
 */
typedef struct _Signature {
    int8_t alg;
    DPS_KeyId kid;
    uint8_t* sig;
    size_t sigLen;
} Signature;

static volatile void* SecureZeroMemory(volatile void* m, size_t l)
{
    volatile uint8_t* p = m;
    while (l--) {
        *p++ = 0;
    }
    return m;
}

static DPS_Status SetCryptoParams(int8_t alg, uint8_t* M, size_t* nonceLen)
{
    switch (alg) {
    case COSE_ALG_A256GCM:
        *M = 128 / 8;
        *nonceLen = AES_GCM_NONCE_LEN;
        break;
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
    return DPS_OK;
}

static DPS_Status EncodeProtectedMap(DPS_TxBuffer* buf, int8_t alg)
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
        ret = CBOR_EncodeInt8(buf, COSE_HDR_ALG);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, alg);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EndWrapBytes(buf, wrapPtr);
    }
    return ret;
}

static DPS_Status EncodeUnprotectedMap(DPS_TxBuffer* buf, const uint8_t* kid, size_t kidLen,
                                       const uint8_t* nonce, size_t nonceLen, Signature* sig)
{
    size_t n;
    DPS_Status ret;

    n = 0;
    if (kid && kidLen) {
        ++n;
    }
    if (nonce && nonceLen) {
        ++n;
    }
    if (sig) {
        ++n;
    }
    ret = CBOR_EncodeMap(buf, n);
    if (kid && kidLen) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeInt8(buf, COSE_HDR_KID);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeBytes(buf, kid, kidLen);
        }
    }
    if (nonce && nonceLen) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeInt8(buf, COSE_HDR_IV);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeBytes(buf, nonce, nonceLen);
        }
    }
    if (sig) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeInt8(buf, COSE_HDR_COUNTER_SIGNATURE);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeArray(buf, 3);
        }
        if (ret == DPS_OK) {
            ret = EncodeProtectedMap(buf, sig->alg);
        }
        if (ret == DPS_OK) {
            ret = EncodeUnprotectedMap(buf, sig->kid.id, sig->kid.len, NULL, 0, NULL);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeBytes(buf, sig->sig, sig->sigLen);
        }
    }
    return ret;
}

static DPS_Status EncodeRecipient(DPS_TxBuffer* buf, int8_t alg, const DPS_KeyId* kid,
                                  COSE_Key* key, const uint8_t* content, size_t contentLen)
{
    DPS_Status ret;
    size_t len = 0;

    ret = CBOR_EncodeArray(buf, 3);
    /*
     * [1] Protected headers
     */
    if (ret == DPS_OK) {
        switch (alg) {
        case COSE_ALG_A256KW:
        case COSE_ALG_DIRECT:
            ret = CBOR_EncodeBytes(buf, NULL, 0);
            break;
        case COSE_ALG_ECDH_ES_A256KW:
            ret = EncodeProtectedMap(buf, alg);
            break;
        default:
            ret = DPS_ERR_NOT_IMPLEMENTED;
            break;
        }
    }
    /*
     * [2] Unprotected map
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeMap(buf, 2);
    }
    if (ret == DPS_OK) {
        switch (alg) {
        case COSE_ALG_A256KW:
        case COSE_ALG_DIRECT:
            ret = CBOR_EncodeInt8(buf, COSE_HDR_ALG);
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, alg);
            }
            break;
        case COSE_ALG_ECDH_ES_A256KW:
            if (!key || key->type != COSE_KEY_EC) {
                ret = DPS_ERR_INVALID;
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_HDR_EPHEMERAL_KEY);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeMap(buf, 4);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_KEY_KTY);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_KEY_KTY_EC);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_EC_KEY_CRV);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, key->ec.curve);
            }
            if (ret == DPS_OK) {
                len = CoordinateSize_EC(key->ec.curve);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_EC_KEY_X);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeBytes(buf, key->ec.x, len);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeInt8(buf, COSE_EC_KEY_Y);
            }
            if (ret == DPS_OK) {
                ret = CBOR_EncodeBytes(buf, key->ec.y, len);
            }
            break;
        }
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, COSE_HDR_KID);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, kid->id, kid->len);
    }
    /*
     * [3] Encrypted byte string
     */
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, content, contentLen);
    }
    return ret;
}

/*
 * Encodes a Sig_structure used in the COSE signing and verification
 * process.
 *
 * Sig_structure = [
 *     context : "Signature" / "Signature1" / "CounterSignature",
 *     body_protected : empty_or_serialized_map,
 *     ? sign_protected : empty_or_serialized_map,
 *     external_aad : bstr,
 *     payload : bstr
 * ]
 */
static DPS_Status EncodeSig(DPS_Node* node, DPS_TxBuffer* buf, int8_t alg, int8_t sigAlg,
                            uint8_t* aad, size_t aadLen,
                            const uint8_t* payload, size_t payloadLen)
{
    DPS_Status ret;
    size_t bufLen;

    bufLen = CBOR_SIZEOF_ARRAY(5) +
        CBOR_SIZEOF_STATIC_STRING(COUNTER_SIGNATURE) +
        SIZEOF_PROTECTED_MAP +
        SIZEOF_PROTECTED_MAP +
        CBOR_SIZEOF_BYTES(aadLen) +
        CBOR_SIZEOF_BYTES(payloadLen);

    ret = DPS_TxBufferReserve(node, buf, bufLen, DPS_TMP_POOL);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(buf, 5);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeString(buf, COUNTER_SIGNATURE);
    }
    if (ret == DPS_OK) {
        ret = EncodeProtectedMap(buf, alg);
    }
    if (ret == DPS_OK) {
        ret = EncodeProtectedMap(buf, sigAlg);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, aad, aadLen);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, payload, payloadLen);
    }
    DPS_TxBufferCommit(buf);
    return ret;
}

/*
 * Encodes an Enc_structure used in the COSE encryption and decryption
 * process.
 *
 * Enc_structure = [
 *     context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
 *         "Mac_Recipient" / "Rec_Recipient",
 *     protected : empty_or_serialized_map,
 *     external_aad : bstr
 * ]
 */
static DPS_Status EncodeAAD(DPS_Node* node, DPS_TxBuffer* buf, uint8_t tag, int8_t alg, uint8_t* aad, size_t aadLen)
{
    DPS_Status ret;
    const char* context;
    size_t bufLen;

    bufLen = CBOR_SIZEOF_ARRAY(3) +
        SIZEOF_PROTECTED_MAP +
        CBOR_SIZEOF_BYTES(aadLen);
    switch (tag) {
    case COSE_TAG_ENCRYPT0:
        bufLen += CBOR_SIZEOF_STATIC_STRING(ENCRYPT0);
        context = ENCRYPT0;
        break;
    case COSE_TAG_ENCRYPT:
        bufLen += CBOR_SIZEOF_STATIC_STRING(ENCRYPT);
        context = ENCRYPT;
        break;
    default:
        return DPS_ERR_INVALID;
    }

    ret = DPS_TxBufferReserve(node, buf, bufLen, DPS_TMP_POOL);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(buf, 3);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeString(buf, context);
    }
    if (ret == DPS_OK) {
        ret = EncodeProtectedMap(buf, alg);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeBytes(buf, aad, aadLen);
    }
    DPS_TxBufferCommit(buf);
    return ret;
}

/*
 * Encodes a PartyInfo structure used in the HKDF process.
 *
 * PartyInfo = (
 *     identity : bstr / nil,
 *     nonce : bstr / int / nil,
 *     other : bstr / nil
 * )
 */
static DPS_Status EncodePartyInfo(DPS_TxBuffer* buf)
{
    DPS_Status ret;

    ret = CBOR_EncodeArray(buf, 3);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeNull(buf);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeNull(buf);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeNull(buf);
    }
    return ret;
}

/*
 * Encodes a COSE_KDF_Context structure used in the HKDF process.
 *
 * COSE_KDF_Context = [
 *     AlgorithmID : int / tstr,
 *     PartyUInfo : [ PartyInfo ],
 *     PartyVInfo : [ PartyInfo ],
 *     SuppPubInfo : [
 *         keyDataLength : uint,
 *         protected : empty_or_serialized_map,
 *         ? other : bstr
 *     ],
 *     ? SuppPrivInfo : bstr
 * ]
 *
 * @param alg content encryption algorithm
 * @param keyLen size of key data in bytes
 * @param recipientAlg key encryption algorithm
 */
static DPS_Status EncodeKDFContext(DPS_Node* node, DPS_TxBuffer* buf, int8_t alg, uint8_t keyLen, int8_t recipientAlg)
{
    DPS_Status ret;
    size_t bufLen;

    bufLen = CBOR_SIZEOF_ARRAY(4) +
        /* alg */ CBOR_SIZEOF(int8_t) +
        SIZEOF_PARTY_INFO +
        SIZEOF_PARTY_INFO +
        CBOR_SIZEOF_ARRAY(2) +
        CBOR_SIZEOF(uint16_t) +
        SIZEOF_PROTECTED_MAP;

    ret = DPS_TxBufferReserve(node, buf, bufLen, DPS_TMP_POOL);
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(buf, 4);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeInt8(buf, alg);
    }
    if (ret == DPS_OK) {
        ret = EncodePartyInfo(buf);
    }
    if (ret == DPS_OK) {
        ret = EncodePartyInfo(buf);
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeArray(buf, 2);
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint(buf, keyLen * 8);
        }
        if (ret == DPS_OK) {
            ret = EncodeProtectedMap(buf, recipientAlg);
        }
    }
    if (ret == DPS_OK) {
        DPS_TxBufferCommit(buf);
    }
    return ret;
}

static DPS_Status KeyResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    COSE_Key* ckey = (COSE_Key*)data;
    DPS_Status ret;
    size_t len;

    switch (key->type) {
    case DPS_KEY_SYMMETRIC:
        if (ckey->type != COSE_KEY_SYMMETRIC) {
            DPS_ERRPRINT("Provided key has invalid type %d\n", key->type);
            return DPS_ERR_MISSING;
        }
        if (key->symmetric.len != AES_256_KEY_LEN) {
            DPS_ERRPRINT("Provided key has invalid size %d\n", key->symmetric.len);
            return DPS_ERR_MISSING;
        }
        memcpy(ckey->symmetric.key, key->symmetric.key, key->symmetric.len);
        break;
    case DPS_KEY_EC:
        if (ckey->type != COSE_KEY_EC) {
            DPS_ERRPRINT("Provided key has invalid type %d\n", key->type);
            return DPS_ERR_MISSING;
        }
        switch (key->ec.curve) {
        case DPS_EC_CURVE_P384: len = 48; break;
        case DPS_EC_CURVE_P521: len = 66; break;
        default:
            DPS_ERRPRINT("Provided key has unsupported curve %d\n", key->ec.curve);
            return DPS_ERR_MISSING;
        }
        memset(&ckey->ec, 0, sizeof(ckey->ec));
        ckey->ec.curve = key->ec.curve;
        if (key->ec.x) {
            memcpy(ckey->ec.x, key->ec.x, len);
        }
        if (key->ec.y) {
            memcpy(ckey->ec.y, key->ec.y, len);
        }
        if (key->ec.d) {
            memcpy(ckey->ec.d, key->ec.d, len);
        }
        break;
    case DPS_KEY_EC_CERT:
        if (ckey->type != COSE_KEY_EC) {
            DPS_ERRPRINT("Provided key has invalid type %d\n", key->type);
            return DPS_ERR_MISSING;
        }
        if (key->cert.privateKey) {
            ret = ParsePrivateKey_ECDSA(key->cert.privateKey, key->cert.password, &ckey->ec.curve, ckey->ec.d);
            if (ret != DPS_OK) {
                return ret;
            }
        }
        if (key->cert.cert) {
            ret = ParseCertificate_ECDSA(key->cert.cert, &ckey->ec.curve, ckey->ec.x, ckey->ec.y);
            if (ret != DPS_OK) {
                return ret;
            }
        }
        break;
    default:
        DPS_ERRPRINT("Unsupported key type %d\n", key->type);
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status GetKey(DPS_KeyStore* keyStore, const DPS_KeyId* kid, COSE_Key* key)
{
    if (!keyStore || !keyStore->keyRequest) {
        return DPS_ERR_MISSING;
    }
    return keyStore->keyRequest(keyStore, kid, KeyResponse, key);
}

static DPS_Status GetEphemeralKey(DPS_KeyStore* keyStore, COSE_Key* key)
{
    DPS_Key k;

    if (!keyStore || !keyStore->ephemeralKeyRequest) {
        return DPS_ERR_MISSING;
    }
    memset(&k, 0, sizeof(k));
    switch (key->type) {
    case COSE_KEY_SYMMETRIC:
        k.type = DPS_KEY_SYMMETRIC;
        break;
    case COSE_KEY_EC:
        k.type = DPS_KEY_EC;
        k.ec.curve = key->ec.curve;
        break;
    default:
        return DPS_ERR_MISSING;
    }
    return keyStore->ephemeralKeyRequest(keyStore, &k, KeyResponse, key);
}

static DPS_Status GetSignatureKey(DPS_KeyStore* keyStore, const Signature* sig, COSE_Key* key)
{
    DPS_Status ret;
    DPS_ECCurve curve;

    if (!keyStore || !keyStore->keyRequest) {
        return DPS_ERR_MISSING;
    }
    switch (sig->alg) {
    case COSE_ALG_ES384:
        curve = DPS_EC_CURVE_P384;
        break;
    case COSE_ALG_ES512:
        curve = DPS_EC_CURVE_P521;
        break;
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
    key->type = COSE_KEY_EC;
    ret = keyStore->keyRequest(keyStore, &sig->kid, KeyResponse, key);
    if (ret != DPS_OK) {
        return ret;
    }
    if (key->ec.curve != curve) {
        return DPS_ERR_INVALID;
    }
    return DPS_OK;
}

DPS_Status COSE_Encrypt(DPS_Node* node,
                        int8_t alg,
                        const uint8_t nonce[COSE_NONCE_LEN],
                        const COSE_Entity* signer,
                        const COSE_Entity* recipient, size_t recipientLen,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* plainText,
                        DPS_KeyStore* keyStore,
                        DPS_TxBuffer* cipherText)
{
    DPS_Status ret;
    uint8_t tag;
    size_t recipientBytes;
    size_t ptLen;
    DPS_TxBuffer AAD;
    size_t aadLen;
    Signature sig;
    DPS_TxBuffer toBeSigned;
    DPS_TxBuffer sigBuf;
    COSE_Key ephemeralKey;
    COSE_Key staticKey;
    uint8_t secret[ECDH_MAX_SHARED_SECRET_LEN];
    size_t secretLen;
    DPS_TxBuffer kdfContext;
    COSE_Key cek;
    COSE_Key k;
    uint8_t M;
    size_t nonceLen;
    DPS_TxBuffer content;
    size_t ctLen;
    size_t i;

    DPS_DBGTRACE();

    if (!recipient || !recipientLen || !aad || !plainText) {
        return DPS_ERR_ARGS;
    }

    recipientBytes = 0;
    for (i = 0; i < recipientLen; ++i) {
        recipientBytes += SIZEOF_RECIPIENT(recipient[i].kid.len);
        /*
         * Recipient algorithms must agree as the content key shared
         * between the recipients depends on the algorithm
         */
        if (recipient[i].alg != recipient[0].alg) {
            return DPS_ERR_ARGS;
        }
    }

    ptLen = DPS_RxBufferAvail(plainText);
    memset(&ephemeralKey, 0, sizeof(ephemeralKey));
    if ((recipientLen == 1) && (recipient[0].alg == COSE_ALG_RESERVED)) {
        tag = COSE_TAG_ENCRYPT0;
    } else {
        tag = COSE_TAG_ENCRYPT;
    }

    ret = SetCryptoParams(alg, &M, &nonceLen);
    if (ret != DPS_OK) {
        goto Exit;
    }

    /*
     * Create and encode the AAD
     */
    ret = EncodeAAD(node, &AAD, tag, alg, aad->base, DPS_RxBufferAvail(aad));
    if (ret != DPS_OK) {
        goto Exit;
    }
    aadLen = DPS_TxBufferUsed(&AAD);
    /*
     * Determine the content encryption key (CEK)
     */
    switch (recipient[0].alg) {
    case COSE_ALG_RESERVED:
        if (recipientLen > 1) {
            ret = DPS_ERR_ARGS;
            goto Exit;
        }
        cek.type = COSE_KEY_SYMMETRIC;
        ret = GetKey(keyStore, &recipient[0].kid, &cek);
        if (ret != DPS_OK) {
            goto Exit;
        }
        break;
    case COSE_ALG_DIRECT:
        if (recipientLen > 1) {
            ret = DPS_ERR_ARGS;
            goto Exit;
        }
        cek.type = COSE_KEY_SYMMETRIC;
        ret = GetKey(keyStore, &recipient[0].kid, &cek);
        if (ret != DPS_OK) {
            goto Exit;
        }
        break;
    case COSE_ALG_A256KW:
        cek.type = COSE_KEY_SYMMETRIC;
        ret = GetEphemeralKey(keyStore, &cek);
        if (ret != DPS_OK) {
            goto Exit;
        }
        break;
    case COSE_ALG_ECDH_ES_A256KW:
        /*
         * Request the random content key
         */
        cek.type = COSE_KEY_SYMMETRIC;
        ret = GetEphemeralKey(keyStore, &cek);
        if (ret != DPS_OK) {
            goto Exit;
        }
        break;
    default:
        ret = DPS_ERR_NOT_IMPLEMENTED;
        goto Exit;
    }
    /*
     * Call the encryption algorithm
     */
    ret = DPS_TxBufferReserve(node, &content, ptLen + M, DPS_TMP_POOL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = Encrypt_GCM(cek.symmetric.key, nonce, plainText->base, ptLen, AAD.base, aadLen, &content);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * Countersign the content
     */
    if (signer) {
        ret = DPS_TxBufferReserve(node, &sigBuf, SIZEOF_SIGNATURE, DPS_TMP_POOL);
        if (ret != DPS_OK) {
            goto Exit;
        }
        sig.alg = signer->alg;
        sig.kid = signer->kid;
        ret = EncodeSig(node, &toBeSigned, alg, sig.alg, NULL, 0, content.base, DPS_TxBufferUsed(&content));
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = GetSignatureKey(keyStore, &sig, &k);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = Sign_ECDSA(k.ec.curve, k.ec.d, toBeSigned.base, DPS_TxBufferUsed(&toBeSigned), &sigBuf);
        if (ret != DPS_OK) {
            goto Exit;
        }
        sig.sig = sigBuf.base;
        sig.sigLen = DPS_TxBufferUsed(&sigBuf);
        DPS_TxBufferCommit(&sigBuf);
    }
    /*
     * Allocate cipherText buffer and copy in headers
     */
    ctLen = CBOR_SIZEOF(tag) +
        CBOR_SIZEOF_ARRAY(4) +
        SIZEOF_PROTECTED_MAP +
        CBOR_SIZEOF_MAP(2) +
        /* iv */ CBOR_SIZEOF(int8_t) + CBOR_SIZEOF_BYTES(COSE_NONCE_LEN) +
        CBOR_SIZEOF_BYTES(DPS_TxBufferUsed(&content));
    if (signer) {
        ctLen += /* counter signature */ CBOR_SIZEOF(int8_t) + SIZEOF_COUNTER_SIGNATURE(sig.kid.len);
    }
    if (tag == COSE_TAG_ENCRYPT) {
        ctLen += CBOR_SIZEOF_ARRAY(recipientLen) + recipientBytes;
    }
    ret = DPS_TxBufferReserve(node, cipherText, ctLen, DPS_TX_POOL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * Prefix with the COSE tag
     */
    ret = CBOR_EncodeTag(cipherText, tag);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * Output is a CBOR array of 3 or 4 elements
     */
    ret = CBOR_EncodeArray(cipherText, (tag == COSE_TAG_ENCRYPT) ? 4 : 3);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [1] Protected headers
     */
    ret = EncodeProtectedMap(cipherText, alg);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [2] Unprotected map
     */
    ret = EncodeUnprotectedMap(cipherText, NULL, 0, nonce, nonceLen, signer ? &sig : NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [3] Encrypted content
     */
    ret = CBOR_EncodeLength(cipherText, DPS_TxBufferUsed(&content), CBOR_BYTES);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = CBOR_Copy(cipherText, content.base, DPS_TxBufferUsed(&content));
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [4] Recipients
     */
    if (tag == COSE_TAG_ENCRYPT) {
        ret = CBOR_EncodeArray(cipherText, recipientLen);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /*
         * For recipients of the message, recursively perform the
         * encryption algorithm for that recipient, using CEK as the
         * plaintext.
         */
        for (i = 0; i < recipientLen; ++i) {
            uint8_t kw[AES_256_KEY_WRAP_LEN];
            switch (recipient[i].alg) {
            case COSE_ALG_RESERVED:
                assert(tag == COSE_TAG_ENCRYPT0);
                break;
            case COSE_ALG_DIRECT:
                ret = EncodeRecipient(cipherText, recipient[i].alg, &recipient[i].kid, NULL, NULL, 0);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                break;
            case COSE_ALG_A256KW:
                k.type = COSE_KEY_SYMMETRIC;
                ret = GetKey(keyStore, &recipient[i].kid, &k);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                ret = KeyWrap(cek.symmetric.key, k.symmetric.key, kw);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                ret = EncodeRecipient(cipherText, recipient[i].alg, &recipient[i].kid, NULL, kw, sizeof(kw));
                if (ret != DPS_OK) {
                    goto Exit;
                }
                break;
            case COSE_ALG_ECDH_ES_A256KW:
                /*
                 * Request the static recipient public key and ephemeral sender private key
                 *
                 * Assume that all the recipients will use the same EC curve and attempt to
                 * request only one ephemeral key per message.
                 */
                staticKey.type = COSE_KEY_EC;
                ret = GetKey(keyStore, &recipient[i].kid, &staticKey);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                if (ephemeralKey.ec.curve != staticKey.ec.curve) {
                    ephemeralKey.type = COSE_KEY_EC;
                    ephemeralKey.ec.curve = staticKey.ec.curve;
                    ret = GetEphemeralKey(keyStore, &ephemeralKey);
                    if (ret != DPS_OK) {
                        goto Exit;
                    }
                }
                /*
                 * Create the key encryption key using ECDH + HKDF
                 */
                ret = ECDH(staticKey.ec.curve, staticKey.ec.x, staticKey.ec.y, ephemeralKey.ec.d, secret, &secretLen);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                ret = EncodeKDFContext(node, &kdfContext, COSE_ALG_A256KW, AES_256_KEY_LEN, recipient[i].alg);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                k.type = COSE_KEY_SYMMETRIC;
                ret = HKDF_SHA256(secret, secretLen, kdfContext.base, DPS_TxBufferUsed(&kdfContext), k.symmetric.key);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                /*
                 * Wrap the content encryption key
                 */
                ret = KeyWrap(cek.symmetric.key, k.symmetric.key, kw);
                if (ret != DPS_OK) {
                    goto Exit;
                }
                ret = EncodeRecipient(cipherText, recipient[i].alg, &recipient[i].kid, &ephemeralKey, kw, sizeof(kw));
                if (ret != DPS_OK) {
                    goto Exit;
                }
                break;
            }
        }
    }

Exit:
    return ret;
}

/*
 * Decodes a COSE_Key structure.
 *
 * COSE_Key = {
 *     1 => tstr / int,          ; kty
 *     ? 2 => bstr,              ; kid
 *     ? 3 => tstr / int,        ; alg
 *     ? 4 => [+ (tstr / int) ], ; key_ops
 *     ? 5 => bstr,              ; Base IV
 *     * label => values
 * }
 *
 * Only decoding of EC2 key types is implemented.
 */
static DPS_Status DecodeKey(DPS_RxBuffer* buf, COSE_Key* key)
{
    DPS_Status ret;
    size_t size;
    int8_t mapKey;
    int8_t kty;
    size_t csz = 0;

    ret = CBOR_DecodeMap(buf, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    /* First entry in map must be key type */
    if (size < 1) {
        return DPS_ERR_INVALID;
    }
    ret = CBOR_DecodeInt8(buf, &mapKey);
    if (ret != DPS_OK) {
        return ret;
    }
    if (mapKey == COSE_KEY_KTY) {
        ret = CBOR_DecodeInt8(buf, &kty);
    } else {
        ret = DPS_ERR_INVALID;
    }
    if (ret != DPS_OK) {
        return ret;
    }
    while (--size) {
        uint8_t maj;
        uint8_t* bytes;
        size_t sz;

        ret = CBOR_DecodeInt8(buf, &mapKey);
        if (ret != DPS_OK) {
            return ret;
        }
        switch (kty) {
        case COSE_KEY_KTY_EC:
            key->type = COSE_KEY_EC;
            switch (mapKey) {
            case COSE_EC_KEY_CRV:
                ret = CBOR_Peek(buf, &maj, NULL);
                if (ret != DPS_OK) {
                    return ret;
                }
                if (maj == CBOR_STRING) {
                    ret = DPS_ERR_NOT_IMPLEMENTED;
                } else {
                    int8_t crv;
                    ret = CBOR_DecodeInt8(buf, &crv);
                    if ((ret == DPS_OK) && ((crv < DPS_EC_CURVE_P384) || (DPS_EC_CURVE_P521 < crv))) {
                        ret = DPS_ERR_NOT_IMPLEMENTED;
                    }
                    if (ret == DPS_OK) {
                        key->ec.curve = crv;
                    }
                }
                if (ret != DPS_OK) {
                    return ret;
                }
                csz = CoordinateSize_EC(key->ec.curve);
                if (!csz) {
                    ret = DPS_ERR_NOT_IMPLEMENTED;
                }
                break;
            case COSE_EC_KEY_X:
                ret = CBOR_DecodeBytes(buf, &bytes, &sz);
                if (ret != DPS_OK) {
                    return ret;
                }
                if (sz != csz || sz > EC_MAX_COORD_LEN) {
                    return DPS_ERR_INVALID;
                }
                memcpy(key->ec.x, bytes, sz);
                break;
            case COSE_EC_KEY_Y:
                ret = CBOR_Peek(buf, &maj, NULL);
                if (ret != DPS_OK) {
                    return ret;
                }
                if (maj != CBOR_BYTES) {
                    return DPS_ERR_NOT_IMPLEMENTED;
                }
                ret = CBOR_DecodeBytes(buf, &bytes, &sz);
                if (ret != DPS_OK) {
                    return ret;
                }
                if (sz != csz || sz > EC_MAX_COORD_LEN) {
                    return DPS_ERR_INVALID;
                }
                memcpy(key->ec.y, bytes, sz);
                break;
            default:
                return DPS_ERR_INVALID;
            }
            break;
        default:
            return DPS_ERR_INVALID;
        }
    }
    return ret;
}

/*
 * Decode the protected headers.
 *
 * @param alg The algorithm.  COSE_ALG_RESERVED if not present.
 */
static DPS_Status DecodeProtectedMap(DPS_RxBuffer* buf, int8_t* alg)
{
    DPS_Status ret;
    size_t size;
    int64_t key;
    uint8_t* map;
    DPS_RxBuffer mapBuf;

    *alg = COSE_ALG_RESERVED;

    /*
     * Protected map is wrapped inside a byte string
     */
    ret = CBOR_DecodeBytes(buf, &map, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    if (!size) {
        /*
         * An empty protected map is valid inside a COSE_Entity
         * structure.
         */
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
    if (key == COSE_HDR_ALG) {
        ret = CBOR_DecodeInt8(&mapBuf, alg);
    } else {
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

static DPS_Status DecodeUnprotectedMap(DPS_RxBuffer* buf,
                                       int8_t* alg,
                                       DPS_KeyId* kid,
                                       uint8_t* nonce,
                                       Signature* sig,
                                       COSE_Key* key)
{
    DPS_Status ret;
    size_t size, sz;

    ret = CBOR_DecodeMap(buf, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    while (size--) {
        int8_t mapKey;
        uint8_t* data;
        size_t len;

        ret = CBOR_DecodeInt8(buf, &mapKey);
        if (ret != DPS_OK) {
            return ret;
        }
        switch (mapKey) {
        case COSE_HDR_ALG:
            if (!alg) {
                return DPS_ERR_INVALID;
            }
            ret = CBOR_DecodeInt8(buf, alg);
            if (ret != DPS_OK) {
                return ret;
            }
            break;
        case COSE_HDR_KID:
            if (!kid) {
                return DPS_ERR_INVALID;
            }
            ret = CBOR_DecodeBytes(buf, (uint8_t**)&data, &len);
            if (ret != DPS_OK) {
                return ret;
            }
            if (len > DPS_MAX_KEY_ID_LEN) {
                DPS_DBGPRINT("Key id is too long %d\n", len);
                return DPS_ERR_RESOURCES;
            }
            kid->len = len;
            memcpy(kid->id, data, kid->len);
            break;
        case COSE_HDR_IV:
            if (!nonce) {
                return DPS_ERR_INVALID;
            }
            ret = CBOR_DecodeBytes(buf, &data, &len);
            if (ret != DPS_OK) {
                return ret;
            }
            if (len > COSE_NONCE_LEN) {
                return DPS_ERR_INVALID;
            }
            memcpy(nonce, data, len);
            break;
        case COSE_HDR_COUNTER_SIGNATURE:
            if (!sig) {
                return DPS_ERR_INVALID;
            }
            ret = CBOR_DecodeArray(buf, &sz);
            if (ret != DPS_OK) {
                return ret;
            }
            if (sz != 3) {
                return DPS_ERR_INVALID;
            }
            ret = DecodeProtectedMap(buf, &sig->alg);
            if ((ret != DPS_OK) || (sig->alg == COSE_ALG_RESERVED)) {
                return DPS_ERR_INVALID;
            }
            ret = DecodeUnprotectedMap(buf, NULL, &sig->kid, NULL, NULL, NULL);
            if (ret != DPS_OK) {
                return ret;
            }
            ret = CBOR_DecodeBytes(buf, &sig->sig, &sig->sigLen);
            if (ret != DPS_OK) {
                return ret;
            }
            break;
        case COSE_HDR_EPHEMERAL_KEY:
            if (!key) {
                return DPS_ERR_INVALID;
            }
            ret = DecodeKey(buf, key);
            if (ret != DPS_OK) {
                return ret;
            }
            break;
        default:
            return DPS_ERR_INVALID;
        }
    }
    return ret;
}

static DPS_Status DecodeRecipient(DPS_RxBuffer* buf,
                                  int8_t* alg,
                                  DPS_KeyId* kid,
                                  COSE_Key* key,
                                  uint8_t** content,
                                  size_t *contentLen)
{
    DPS_Status ret;
    size_t size;

    ret = CBOR_DecodeArray(buf, &size);
    if (ret != DPS_OK) {
        return ret;
    }
    if (size != 3) {
        return DPS_ERR_INVALID;
    }
    ret = DecodeProtectedMap(buf, alg);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = DecodeUnprotectedMap(buf, alg, kid, NULL, NULL, key);
    if (ret != DPS_OK) {
        return ret;
    }
    ret = CBOR_DecodeBytes(buf, content, contentLen);
    if (ret != DPS_OK) {
        return ret;
    }
    return ret;
}

DPS_Status COSE_Decrypt(DPS_Node* node,
                        const uint8_t* nonce,
                        COSE_Entity* recipient,
                        DPS_RxBuffer* aad,
                        DPS_RxBuffer* cipherText,
                        DPS_KeyStore* keyStore,
                        COSE_Entity* signer,
                        DPS_TxBuffer* plainText)
{
    DPS_Status ret;
    DPS_TxBuffer AAD;
    size_t aadLen;
    uint64_t tag;
    size_t sz;
    int8_t alg;
    uint8_t M;
    uint8_t iv[COSE_NONCE_LEN];
    size_t ivLen;
    Signature sig;
    uint8_t* content;
    size_t contentLen;
    DPS_TxBuffer toBeSigned;
    COSE_Key k;
    uint8_t* kw = NULL;
    size_t kwLen = 0;
    COSE_Key kek;
    DPS_TxBuffer kdfContext;
    COSE_Key ephemeralKey;
    COSE_Key staticKey;
    uint8_t secret[ECDH_MAX_SHARED_SECRET_LEN];
    size_t secretLen;
    COSE_Key cek;
    size_t i;

    DPS_DBGTRACE();

    if (!aad || !cipherText || !plainText) {
        return DPS_ERR_ARGS;
    }

    memset(&sig, 0, sizeof(sig));
    memset(&k, 0, sizeof(k));
    if (signer) {
        memset(signer, 0, sizeof(*signer));
    }

    /*
     * Check this is a COSE payload
     */
    ret = CBOR_DecodeTag(cipherText, &tag);
    if ((ret != DPS_OK) || ((tag != COSE_TAG_ENCRYPT0) && (tag != COSE_TAG_ENCRYPT))) {
        ret = DPS_ERR_NOT_ENCRYPTED;
        goto Exit;
    }
    /*
     * Input is a CBOR array of 3 or 4 elements
     */
    ret = CBOR_DecodeArray(cipherText, &sz);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if ((tag == COSE_TAG_ENCRYPT0 && sz != 3) || (tag == COSE_TAG_ENCRYPT && sz != 4)) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }
    /*
     * [1] Protected headers
     */
    ret = DecodeProtectedMap(cipherText, &alg);
    if ((ret != DPS_OK) || (alg == COSE_ALG_RESERVED)) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }
    ret = SetCryptoParams(alg, &M, &ivLen);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [2] Unprotected map
     */
    ret = DecodeUnprotectedMap(cipherText, NULL, NULL, iv, &sig, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * [3] Encrypted content
     */
    ret = CBOR_DecodeBytes(cipherText, &content, &contentLen);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /*
     * Verify signature of encrypted content
     */
    if (sig.sigLen) {
        ret = EncodeSig(node, &toBeSigned, alg, sig.alg, NULL, 0, content, contentLen);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = GetSignatureKey(keyStore, &sig, &k);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("Failed to get signature key: %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
        ret = Verify_ECDSA(k.ec.curve, k.ec.x, k.ec.y, toBeSigned.base, DPS_TxBufferUsed(&toBeSigned),
                           sig.sig, sig.sigLen);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("Failed to verify signature: %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
        if (signer) {
            signer->alg = sig.alg;
            signer->kid = sig.kid;
        }
    }
    /*
     * Create and encode the AAD
     */
    ret = EncodeAAD(node, &AAD, (uint8_t)tag, alg, aad->base, DPS_RxBufferAvail(aad));
    if (ret != DPS_OK) {
        goto Exit;
    }
    aadLen = DPS_TxBufferUsed(&AAD);
    /*
     * Determine the content encryption key (CEK)
     */
    if (tag == COSE_TAG_ENCRYPT0) {
        sz = 1;
        recipient->alg = COSE_ALG_RESERVED;
    } else {
        ret = CBOR_DecodeArray(cipherText, &sz);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    for (i = 0; i < sz; ++i) {
        if (tag == COSE_TAG_ENCRYPT) {
            ret = DecodeRecipient(cipherText, &recipient->alg, &recipient->kid, &ephemeralKey, &kw, &kwLen);
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
        switch (recipient->alg) {
        case COSE_ALG_RESERVED:
            cek.type = COSE_KEY_SYMMETRIC;
            ret = GetKey(keyStore, &recipient->kid, &cek);
            if (ret != DPS_OK) {
                continue;
            }
            break;
        case COSE_ALG_DIRECT:
            cek.type = COSE_KEY_SYMMETRIC;
            ret = GetKey(keyStore, &recipient->kid, &cek);
            if (ret != DPS_OK) {
                continue;
            }
            break;
        case COSE_ALG_A256KW:
            kek.type = COSE_KEY_SYMMETRIC;
            ret = GetKey(keyStore, &recipient->kid, &kek);
            if (ret != DPS_OK) {
                continue;
            }
            if (!kw || (kwLen != AES_256_KEY_WRAP_LEN)) {
                ret = DPS_ERR_INVALID;
                continue;
            }
            cek.type = COSE_KEY_SYMMETRIC;
            ret = KeyUnwrap(kw, kek.symmetric.key, cek.symmetric.key);
            if (ret != DPS_OK) {
                continue;
            }
            break;
        case COSE_ALG_ECDH_ES_A256KW:
            if (!kw || (kwLen != AES_256_KEY_WRAP_LEN)) {
                ret = DPS_ERR_INVALID;
                continue;
            }
            /*
             * Request the static recipient private key
             */
            staticKey.type = COSE_KEY_EC;
            ret = GetKey(keyStore, &recipient->kid, &staticKey);
            if (ret != DPS_OK) {
                continue;
            }
            /*
             * Create the key encryption key using ECDH + HKDF
             */
            ret = ECDH(ephemeralKey.ec.curve, ephemeralKey.ec.x, ephemeralKey.ec.y, staticKey.ec.d, secret, &secretLen);
            if (ret != DPS_OK) {
                continue;
            }
            ret = EncodeKDFContext(node, &kdfContext, COSE_ALG_A256KW, AES_256_KEY_LEN, recipient->alg);
            if (ret != DPS_OK) {
                continue;
            }
            kek.type = COSE_KEY_SYMMETRIC;
            ret = HKDF_SHA256(secret, secretLen, kdfContext.base, DPS_TxBufferUsed(&kdfContext), kek.symmetric.key);
            if (ret != DPS_OK) {
                continue;
            }
            /*
             * Unwrap the content encryption key
             */
            cek.type = COSE_KEY_SYMMETRIC;
            ret = KeyUnwrap(kw, kek.symmetric.key, cek.symmetric.key);
            if (ret != DPS_OK) {
                continue;
            }
            break;
        default:
            ret = DPS_ERR_NOT_IMPLEMENTED;
            continue;
        }
        ret = Decrypt_GCM(cek.symmetric.key, nonce ? nonce : iv, content, contentLen, AAD.base, aadLen, plainText);
        if (ret == DPS_OK) {
            break;
        }
    }

Exit:
    return ret;
}
