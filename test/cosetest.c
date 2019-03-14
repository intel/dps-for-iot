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

#include "test.h"
#include "gcm.h"
#include "cose.h"
#include "crypto.h"
#include "ec.h"
#include "keywrap.h"

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
    0x01,0x00,0x00,0x00,0x38,0x5e,0x9a,0xdd,0xd5,0x55,0x88,0xc4
};

static const DPS_UUID _keyId = {
    0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2
};
static const uint8_t _key[] = {
    0x45,0x8c,0x75,0x4f,0x76,0x36,0x5a,0xf7,0x51,0x2d,0xe5,0x52,0xc1,0xc5,0xdd,0x6a,
    0xdf,0x81,0x00,0x91,0x8f,0x85,0x99,0x20,0xf7,0xa8,0xfe,0x85,0xb4,0xf0,0x1f,0xa2
};
const DPS_KeyId keyId = { _keyId.val, sizeof(_keyId.val) };
const DPS_Key key = { DPS_KEY_SYMMETRIC, .symmetric = { _key, sizeof(_key) } };

#define SIGNER_ID "DPS Test Publisher"
static const DPS_KeyId signerId = { (const uint8_t*)SIGNER_ID, sizeof(SIGNER_ID) - 1 };
static const char signerCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIB2jCCATsCCQDtkL14u3NJRDAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
    "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r\n"
    "MDIyNzE4MTQzMlowODELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEbMBkGA1UE\r\n"
    "AwwSRFBTIFRlc3QgUHVibGlzaGVyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB\r\n"
    "igbpvXYHms+7wTa1BcAf3PQF3/6R/J92HcbiPtPGVNlPYdpCnyYEF7DoNvgI/Iag\r\n"
    "EqUjryMWoxwi+KghG1BwA2MAKhn/ta4TAXfASPr9gzYK5g+pKFnOXqc4sWut/o8D\r\n"
    "se6LU2D3PsQBs5/kCkbjz1/sKQVbDJGT5eTHQvC5nxjToZcwCgYIKoZIzj0EAwQD\r\n"
    "gYwAMIGIAkIBIEo4NfnSh60U4srn2iSR/u5VFHi4Yy3PjlKlkmRDo+ClPVHPOK7y\r\n"
    "8/82J1qlTw5GSR0snR4R5663D2s3w2e9fIwCQgCp3K8Y7fTPdpwOy91clBr3OFHK\r\n"
    "sMt3kjq1vrcbVzZy50hGyGxjUqZHUi87/KuhkcMKSqDC6U7jEiEpv/WNH/VrZQ==\r\n"
    "-----END CERTIFICATE-----\r\n";
static const char signerPrivateKey[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "Proc-Type: 4,ENCRYPTED\r\n"
    "DEK-Info: AES-256-CBC,F0004AF499EA7B8A7252B286E3274508\r\n"
    "\r\n"
    "M5Du62n9VNOQjomIiToNODHeUexM6/kd/BJv5htLIKK+IuWhbz7uKiDa1ULrxz5x\r\n"
    "KVEh6b0h3WjQ5Z+tlHGGedD4uarwWcUDaw9j2kTpaN33HuCmQAEgH7Lqtq4BnI4S\r\n"
    "7FDtpoXtMOWGBs/AhQlUXQE0lFENacZ3PLkbafHVzcm19hWZk19ANpZOPbRNgMdQ\r\n"
    "vPIAyubRAwG+M+wtCxoG9kvwA2TpriwTPb3HaTtefXcaxM8ijS/VQa5mFjphSeUn\r\n"
    "BcrDGodlTMw9klV0eJpmDKUrpiXqExhzCsS33jK9YuM=\r\n"
    "-----END EC PRIVATE KEY-----\r\n";
static const char signerPassword[] = "DPS Test Publisher";
const DPS_Key signerKey = { DPS_KEY_EC_CERT, .cert = { signerCert, signerPrivateKey, signerPassword } };

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

static DPS_RBG* rbg = NULL;

static DPS_Status KeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* id)
{
    if ((id->len == keyId.len) && (memcmp(id->id, keyId.id, keyId.len) == 0)) {
        return DPS_SetKey(request, &key);
    } else if ((id->len == signerId.len) && (memcmp(id->id, signerId.id, signerId.len) == 0)) {
        return DPS_SetKey(request, &signerKey);
    } else {
        return DPS_ERR_MISSING;
    }
}

static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    switch (key->type) {
    case DPS_KEY_SYMMETRIC: {
        DPS_Key k;
        uint8_t aes[AES_256_KEY_LEN];
        DPS_Status ret;

        ret = DPS_RandomKey(rbg, aes);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_SYMMETRIC;
        k.symmetric.key = aes;
        k.symmetric.len = AES_256_KEY_LEN;
        return DPS_SetKey(request, &k);
    }
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
}

static void GCM_Raw(void)
{
    DPS_Status ret;
    size_t n;
    uint8_t buf[3][512];
    DPS_RxBuffer msgBuf[3];
    DPS_TxBuffer payload[3];
    DPS_TxBuffer tag;
    DPS_TxBuffer cipherText;
    DPS_TxBuffer plainText;
    uint8_t pt[1024];
    size_t ptLen;
    size_t i;
    size_t test;

    for (test = 0; test < 8; ++test) {
        switch (test) {
        case 0:
            DPS_RxBufferInit(&msgBuf[0], (uint8_t*)msg, sizeof(msg));
            DPS_RxBufferInit(&msgBuf[1], NULL, 0);
            n = 2;
            break;
        case 1:
            for (i = 0; i < 16; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 16);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 0);
            n = 2;
            break;
        case 2:
            for (i = 0; i < 16; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 4; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 16);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 4);
            n = 2;
            break;
        case 3:
            for (i = 0; i < 16; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 20; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 16);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 20);
            n = 2;
            break;
        case 4:
            for (i = 0; i < 20; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 4; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 20);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 4);
            n = 2;
            break;
        case 5:
            for (i = 0; i < 20; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 20; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 20);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 20);
            n = 2;
            break;
        case 6:
            for (i = 0; i < 4; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 20; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 4);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 20);
            n = 2;
            break;
        case 7:
            for (i = 0; i < 4; ++i) {
                buf[0][i] = (uint8_t)i;
            }
            for (i = 0; i < 11; ++i) {
                buf[1][i] = (uint8_t)i;
            }
            for (i = 0; i < 9; ++i) {
                buf[2][i] = (uint8_t)i;
            }
            DPS_RxBufferInit(&msgBuf[0], buf[0], 4);
            DPS_RxBufferInit(&msgBuf[1], buf[1], 11);
            DPS_RxBufferInit(&msgBuf[2], buf[2], 9);
            n = 3;
            break;
        default:
            ASSERT(0);
            break;
        }
        for (i = 0; i < n; ++i) {
            DPS_TxBufferInit(&payload[i], NULL, DPS_RxBufferAvail(&msgBuf[i]));
            DPS_TxBufferAppend(&payload[i], msgBuf[i].base, DPS_RxBufferAvail(&msgBuf[i]));
        }
        DPS_TxBufferInit(&tag, NULL, 16);
        ret = Encrypt_GCM(key.symmetric.key, nonce, payload, n, &tag, aad, sizeof(aad));
        ASSERT(ret == DPS_OK);
        DPS_TxBufferInit(&cipherText, NULL, 512);
        for (i = 0; i < n; ++i) {
            DPS_TxBufferAppend(&cipherText, payload[i].base, DPS_TxBufferUsed(&payload[i]));
        }
        DPS_TxBufferAppend(&cipherText, tag.base, DPS_TxBufferUsed(&tag));
        DPS_TxBufferInit(&plainText, NULL, 512);
        ret = Decrypt_GCM(key.symmetric.key, nonce, cipherText.base, DPS_TxBufferUsed(&cipherText),
                          aad, sizeof(aad), &plainText);
        ASSERT(ret == DPS_OK);

        ptLen = 0;
        for (i = 0; i < n; ++i) {
            memcpy(&pt[ptLen], msgBuf[i].base, msgBuf[i].eod - msgBuf[i].base);
            ptLen += msgBuf[i].eod - msgBuf[i].base;
        }
        ASSERT(DPS_TxBufferUsed(&plainText) == ptLen);
        ASSERT(memcmp(plainText.base, pt, ptLen) == 0);

        for (i = 0; i < n; ++i) {
            DPS_TxBufferFree(&payload[i]);
        }
        DPS_TxBufferFree(&tag);
        DPS_TxBufferFree(&cipherText);
        DPS_TxBufferFree(&plainText);
    }
}

static void ECDSA_VerifyCurve(DPS_ECCurve crv, uint8_t* x, uint8_t* y, uint8_t* d, uint8_t* data, size_t dataLen)
{
    DPS_Status ret;
    DPS_RxBuffer dataBuf;
    DPS_TxBuffer buf;

    DPS_RxBufferInit(&dataBuf, data, dataLen);
    DPS_TxBufferInit(&buf, NULL, 512);
    ret = Sign_ECDSA(crv, d, &dataBuf, 1, &buf);
    ASSERT(ret == DPS_OK);

    ret = Verify_ECDSA(crv, x, y, &dataBuf, 1, buf.base, DPS_TxBufferUsed(&buf));
    ASSERT(ret == DPS_OK);

    DPS_TxBufferFree(&buf);
}

static void ECDSA_Raw(void)
{
    DPS_Status ret;

    uint8_t data[] = {
        0x85, 0x70, 0x43, 0x6F, 0x75, 0x6E, 0x74, 0x65, 0x72, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x43, 0xA1, 0x01, 0x01, 0x44, 0xA1, 0x01, 0x38, 0x23, 0x40, 0x58, 0x24, 0x7A, 0xDB,
        0xE2, 0x70, 0x9C, 0xA8, 0x18, 0xFB, 0x41, 0x5F, 0x1E, 0x5D, 0xF6, 0x6F, 0x4E, 0x1A, 0x51, 0x05,
        0x3B, 0xA6, 0xD6, 0x5A, 0x1A, 0x0C, 0x52, 0xA3, 0x57, 0xDA, 0x7A, 0x64, 0x4B, 0x80, 0x70, 0xA1,
        0x51, 0xB0
    };

    {
        DPS_ECCurve crv = DPS_EC_CURVE_P384;
        uint8_t x[] = {
            0x91, 0x32, 0x72, 0x3f, 0x62, 0x92, 0xb0, 0x10, 0x61, 0x9d, 0xbe, 0x24, 0x8d, 0x69, 0x8c, 0x17,
            0xb5, 0x87, 0x56, 0xc6, 0x39, 0xe7, 0x15, 0x0f, 0x81, 0xbe, 0xe4, 0xeb, 0x8a, 0xc3, 0x72, 0x36,
            0xad, 0x0a, 0x1a, 0x19, 0xd6, 0x7b, 0xe3, 0x2a, 0x66, 0x26, 0x3e, 0x1e, 0x52, 0x4d, 0x12, 0x9c
        };
        uint8_t y[] = {
            0x98, 0xcd, 0x30, 0x78, 0xc5, 0x54, 0xd8, 0x32, 0xac, 0x60, 0x3c, 0x43, 0x26, 0x41, 0x0f, 0xf6,
            0x16, 0x62, 0x45, 0x9b, 0x41, 0xf1, 0xf3, 0xdf, 0x5d, 0xbc, 0xc8, 0x35, 0x98, 0xff, 0x7c, 0x5e,
            0xd8, 0x41, 0x1c, 0xa7, 0x35, 0x67, 0x9d, 0x1c, 0x4c, 0xb3, 0x00, 0x93, 0x97, 0xd9, 0xef, 0x2c
        };
        uint8_t d[] = {
            0xa2, 0x4d, 0xcd, 0xab, 0xde, 0xc0, 0x5e, 0x5a, 0x44, 0xba, 0xc3, 0xbb, 0x8c, 0x8c, 0xb5, 0x15,
            0x90, 0x13, 0x94, 0x13, 0xfd, 0x3c, 0xd4, 0x5e, 0x31, 0x4e, 0xc3, 0x59, 0xb9, 0x0b, 0x43, 0x97,
            0x54, 0xf7, 0x4b, 0x27, 0x1e, 0xeb, 0x87, 0x54, 0x38, 0xc4, 0x3e, 0x6b, 0x55, 0xd1, 0xf4, 0xe8
        };
        ECDSA_VerifyCurve(crv, x, y, d, data, sizeof(data));
    }
    {
        DPS_ECCurve crv = DPS_EC_CURVE_P521;
        uint8_t x[] = {
            0x00, 0x72, 0x99, 0x2c, 0xb3, 0xac, 0x08, 0xec, 0xf3, 0xe5, 0xc6, 0x3d, 0xed, 0xec, 0x0d, 0x51,
            0xa8, 0xc1, 0xf7, 0x9e, 0xf2, 0xf8, 0x2f, 0x94, 0xf3, 0xc7, 0x37, 0xbf, 0x5d, 0xe7, 0x98, 0x66,
            0x71, 0xea, 0xc6, 0x25, 0xfe, 0x82, 0x57, 0xbb, 0xd0, 0x39, 0x46, 0x44, 0xca, 0xaa, 0x3a, 0xaf,
            0x8f, 0x27, 0xa4, 0x58, 0x5f, 0xbb, 0xca, 0xd0, 0xf2, 0x45, 0x76, 0x20, 0x08, 0x5e, 0x5c, 0x8f,
            0x42, 0xad
        };
        uint8_t y[] = {
            0x01, 0xdc, 0xa6, 0x94, 0x7b, 0xce, 0x88, 0xbc, 0x57, 0x90, 0x48, 0x5a, 0xc9, 0x74, 0x27, 0x34,
            0x2b, 0xc3, 0x5f, 0x88, 0x7d, 0x86, 0xd6, 0x5a, 0x08, 0x93, 0x77, 0xe2, 0x47, 0xe6, 0x0b, 0xaa,
            0x55, 0xe4, 0xe8, 0x50, 0x1e, 0x2a, 0xda, 0x57, 0x24, 0xac, 0x51, 0xd6, 0x90, 0x90, 0x08, 0x03,
            0x3e, 0xbc, 0x10, 0xac, 0x99, 0x9b, 0x9d, 0x7f, 0x5c, 0xc2, 0x51, 0x9f, 0x3f, 0xe1, 0xea, 0x1d,
            0x94, 0x75
        };
        uint8_t d[] = {
            0x00, 0x08, 0x51, 0x38, 0xdd, 0xab, 0xf5, 0xca, 0x97, 0x5f, 0x58, 0x60, 0xf9, 0x1a, 0x08, 0xe9,
            0x1d, 0x6d, 0x5f, 0x9a, 0x76, 0xad, 0x40, 0x18, 0x76, 0x6a, 0x47, 0x66, 0x80, 0xb5, 0x5c, 0xd3,
            0x39, 0xe8, 0xab, 0x6c, 0x72, 0xb5, 0xfa, 0xcd, 0xb2, 0xa2, 0xa5, 0x0a, 0xc2, 0x5b, 0xd0, 0x86,
            0x64, 0x7d, 0xd3, 0xe2, 0xe6, 0xe9, 0x9e, 0x84, 0xca, 0x2c, 0x36, 0x09, 0xfd, 0xf1, 0x77, 0xfe,
            0xb2, 0x6d
        };
        uint8_t sig[] = {
            0x00, 0x92, 0x96, 0x63, 0xc8, 0x78, 0x9b, 0xb2, 0x81, 0x77, 0xae, 0x28, 0x46, 0x7e, 0x66, 0x37,
            0x7d, 0xa1, 0x23, 0x02, 0xd7, 0xf9, 0x59, 0x4d, 0x29, 0x99, 0xaf, 0xa5, 0xdf, 0xa5, 0x31, 0x29,
            0x4f, 0x88, 0x96, 0xf2, 0xb6, 0xcd, 0xf1, 0x74, 0x00, 0x14, 0xf4, 0xc7, 0xf1, 0xa3, 0x58, 0xe3,
            0xa6, 0xcf, 0x57, 0xf4, 0xed, 0x6f, 0xb0, 0x2f, 0xcf, 0x8f, 0x7a, 0xa9, 0x89, 0xf5, 0xdf, 0xd0,
            0x7f, 0x07, 0x00, 0xa3, 0xa7, 0xd8, 0xf3, 0xc6, 0x04, 0xba, 0x70, 0xfa, 0x94, 0x11, 0xbd, 0x10,
            0xc2, 0x59, 0x1b, 0x48, 0x3e, 0x1d, 0x2c, 0x31, 0xde, 0x00, 0x31, 0x83, 0xe4, 0x34, 0xd8, 0xfb,
            0xa1, 0x8f, 0x17, 0xa4, 0xc7, 0xe3, 0xdf, 0xa0, 0x03, 0xac, 0x1c, 0xf3, 0xd3, 0x0d, 0x44, 0xd2,
            0x53, 0x3c, 0x49, 0x89, 0xd3, 0xac, 0x38, 0xc3, 0x8b, 0x71, 0x48, 0x1c, 0xc3, 0x43, 0x0c, 0x9d,
            0x65, 0xe7, 0xdd, 0xff
        };
        DPS_RxBuffer dataBuf;
        DPS_RxBufferInit(&dataBuf, data, sizeof(data));
        ret = Verify_ECDSA(crv, x, y, &dataBuf, 1, sig, sizeof(sig));
        ASSERT(ret == DPS_OK);
        ECDSA_VerifyCurve(crv, x, y, d, data, sizeof(data));
    }
}

static void KeyWrap_Raw(void)
{
    const uint8_t kek[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    };
    const uint8_t cek[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    const uint8_t expectedCipherText[] = {
        0x28,0xC9,0xF4,0x04,0xC4,0xB8,0x10,0xF4,0xCB,0xCC,0xB3,0x5C,0xFB,0x87,0xF8,0x26,
        0x3F,0x57,0x86,0xE2,0xD8,0x0E,0xD3,0x26,0xCB,0xC7,0xF0,0xE7,0x1A,0x99,0xF4,0x3B,
        0xFB,0x98,0x8B,0x9B,0x7A,0x02,0xDD,0x21
    };
    uint8_t cipherText[AES_256_KEY_WRAP_LEN];
    DPS_Status ret = KeyWrap(cek, kek, cipherText);
    ASSERT(ret == DPS_OK);
    ASSERT(0 == memcmp(cipherText, expectedCipherText, AES_256_KEY_WRAP_LEN));
    uint8_t unwrappedCek[AES_256_KEY_LEN];
    ret = KeyUnwrap(cipherText, kek, unwrappedCek);
    ASSERT(ret == DPS_OK);
    ASSERT(0 == memcmp(unwrappedCek, cek, AES_256_KEY_LEN));
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_KeyStore* keyStore;
    int i;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    rbg = DPS_CreateRBG();
    keyStore = DPS_CreateKeyStore(NULL, KeyHandler, EphemeralKeyHandler, NULL);

    GCM_Raw();
    ECDSA_Raw();
    KeyWrap_Raw();

    DPS_RxBuffer aadBuf;

    /*
     * Encryption and decryption
     */
    uint8_t alg = COSE_ALG_A256GCM;
    COSE_Entity recipient;
    DPS_TxBuffer cipherText[3];
    DPS_TxBuffer plainText;
    DPS_TxBuffer txBuf;
    DPS_RxBuffer input;
    size_t ctLen;
    DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));
    DPS_TxBufferInit(&cipherText[1], NULL, sizeof(msg));
    DPS_TxBufferAppend(&cipherText[1], (uint8_t*)msg, sizeof(msg));
    recipient.alg = COSE_ALG_A256KW;
    recipient.kid = keyId;
    ret = COSE_Encrypt(alg, nonce, NULL, &recipient, 1, &aadBuf, &cipherText[0], &cipherText[1], 1, &cipherText[2],
                       keyStore);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("COSE_Encrypt failed: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    for (i = 0; i < 3; ++i) {
        Dump("CipherText", cipherText[i].base, DPS_TxBufferUsed(&cipherText[i]));
    }
    /*
     * Turn output buffers into input buffers
     */
    ctLen = 0;
    for (i = 0; i < 3; ++i) {
        ctLen += DPS_TxBufferUsed(&cipherText[i]);
    }
    DPS_TxBufferInit(&txBuf, NULL, ctLen);
    for (i = 0; i < 3; ++i) {
        DPS_TxBufferAppend(&txBuf, cipherText[i].base, DPS_TxBufferUsed(&cipherText[i]));
    }
    DPS_TxBufferToRx(&txBuf, &input);
    DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));
    ret = COSE_Decrypt(nonce, &recipient, &aadBuf, &input, keyStore, NULL, &plainText);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("COSE_Decrypt failed: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    ASSERT(DPS_TxBufferUsed(&plainText) == sizeof(msg));
    ASSERT(memcmp(plainText.base, msg, sizeof(msg)) == 0);
    for (i = 0; i < 3; ++i) {
        DPS_TxBufferFree(&cipherText[i]);
    }
    DPS_TxBufferFree(&cipherText[1]);
    DPS_TxBufferFree(&plainText);
    DPS_TxBufferFree(&txBuf);

    /*
     * Signing and verification
     */
    COSE_Entity signer;
    signer.alg = COSE_ALG_ES512;
    signer.kid = signerId;
    DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));
    DPS_TxBufferInit(&cipherText[1], NULL, sizeof(msg));
    DPS_TxBufferAppend(&cipherText[1], (uint8_t*)msg, sizeof(msg));
    ret = COSE_Sign(&signer, &aadBuf, &cipherText[0], &cipherText[1], 1, &cipherText[2], keyStore);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("COSE_Sign failed: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    for (i = 0; i < 3; ++i) {
        Dump("CipherText", cipherText[i].base, DPS_TxBufferUsed(&cipherText[i]));
    }
    /*
     * Turn output buffers into input buffers
     */
    ctLen = 0;
    for (i = 0; i < 3; ++i) {
        ctLen += DPS_TxBufferUsed(&cipherText[i]);
    }
    DPS_TxBufferInit(&txBuf, NULL, ctLen);
    for (i = 0; i < 3; ++i) {
        DPS_TxBufferAppend(&txBuf, cipherText[i].base, DPS_TxBufferUsed(&cipherText[i]));
    }
    DPS_TxBufferToRx(&txBuf, &input);
    DPS_RxBufferInit(&aadBuf, (uint8_t*)aad, sizeof(aad));
    memset(&signer, 0, sizeof(signer));
    ret = COSE_Verify(&aadBuf, &input, keyStore, &signer);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("COSE_Verify failed: %s\n", DPS_ErrTxt(ret));
        return EXIT_FAILURE;
    }
    ASSERT(signer.kid.len == signerId.len);
    ASSERT(memcmp(signer.kid.id, signerId.id, signer.kid.len) == 0);
    ASSERT(DPS_RxBufferAvail(&input) == sizeof(msg));
    for (i = 0; i < 3; ++i) {
        DPS_TxBufferFree(&cipherText[i]);
    }
    DPS_TxBufferFree(&txBuf);

    DPS_PRINT("Passed\n");
    DPS_DestroyKeyStore(keyStore);
    DPS_DestroyRBG(rbg);
    return EXIT_SUCCESS;
}
