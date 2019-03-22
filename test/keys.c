/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include <safe_lib.h>
#include "keys.h"

static const DPS_UUID _NetworkKeyId = {
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
};
static const uint8_t _NetworkKey[DPS_AES_256_KEY_LEN] = {
    0x11,0x21,0xbb,0xf4,0x9f,0x5e,0xe5,0x5a,0x11,0x86,0x47,0xe6,0x3d,0xc6,0x59,0xa4,
    0xc3,0x1f,0x16,0x56,0x7f,0x1f,0xb8,0x4d,0xe1,0x09,0x28,0x26,0xd5,0xc0,0xf1,0x34
};
const DPS_KeyId NetworkKeyId = { _NetworkKeyId.val, sizeof(_NetworkKeyId.val) };
const DPS_Key NetworkKey = { DPS_KEY_SYMMETRIC, .symmetric = { _NetworkKey, sizeof(_NetworkKey) } };

static const DPS_UUID _PskId[NUM_KEYS] = {
    { .val = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 } },
    { .val = { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc } }
};
static const uint8_t _Psk[NUM_KEYS][DPS_AES_256_KEY_LEN] = {
    { 0xf6,0xeb,0xcb,0xa4,0x25,0xdb,0x3b,0x7e,0x73,0x03,0xe6,0x9c,0x60,0x35,0xae,0x11,
      0xae,0x40,0x0b,0x84,0xf0,0x03,0xcc,0xf9,0xce,0x5c,0x5f,0xd0,0xae,0x51,0x0a,0xcc },
    { 0x2a,0x93,0xff,0x6d,0x96,0x7e,0xb3,0x20,0x85,0x80,0x0e,0x21,0xb0,0x7f,0xa7,0xbe,
      0x3f,0x53,0x68,0x57,0xf9,0x3c,0x7a,0x41,0x59,0xab,0x22,0x2c,0xf8,0xcf,0x08,0x21 }
};
const DPS_KeyId PskId[NUM_KEYS] = {
    { _PskId[0].val, sizeof(_PskId[0].val) },
    { _PskId[1].val, sizeof(_PskId[1].val) },
};
const DPS_Key Psk[NUM_KEYS] = {
    { DPS_KEY_SYMMETRIC, .symmetric = { _Psk[0], sizeof(_Psk[0]) } },
    { DPS_KEY_SYMMETRIC, .symmetric = { _Psk[1], sizeof(_Psk[1]) } }
};

const char TrustedCAs[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICJjCCAYegAwIBAgIJALxrkTEnimvgMAoGCCqGSM49BAMCMCoxCzAJBgNVBAYT\r\n"
    "AlVTMQwwCgYDVQQKDANEUFMxDTALBgNVBAMMBHJvb3QwHhcNMTgwMzAxMTgxMjIx\r\n"
    "WhcNMjgwMjI3MTgxMjIxWjAqMQswCQYDVQQGEwJVUzEMMAoGA1UECgwDRFBTMQ0w\r\n"
    "CwYDVQQDDARyb290MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB/CnbphoNIsQs\r\n"
    "NUKi5YEq6fs1ZJxhbGHdfRz0mjlNNUZ0nuhroEYt29o3Jufr4wiR1Mu/Gk5De10y\r\n"
    "UyGO6VaRXzEA+wMRmkv3YYtyxShBJqVfppUdZ4ACxj4iTjl+ckkkG0hhMaa+4O+E\r\n"
    "CWBqFe8m4F60mB+asrsvcFv8JhmMPCGvgC2jUzBRMB0GA1UdDgQWBBRL8iu+6mhj\r\n"
    "EYw3xhuajof1orBAPzAfBgNVHSMEGDAWgBRL8iu+6mhjEYw3xhuajof1orBAPzAP\r\n"
    "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJCAI4ONDtSU1fE9ZK9\r\n"
    "D2Crp9oyLomhuI0e1ZnoXvyxmayxzDdugY9lMUgXrWIEK9/obC9kyY72pNsptI/2\r\n"
    "VXpO9eLfAkIBpnukkubSeEU03koSqbhQESJbuUpO0n5vpSI5sCHOHQpds1V1VH5f\r\n"
    "jjDgbjFAFw7xKNMu63iHptyzL5fU4W+L8y4=\r\n"
    "-----END CERTIFICATE-----\r\n";

const Id Ids[] = {
    {
        { (const uint8_t*)"alice", sizeof("alice") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBzTCCAS4CCQCu4kaR9/HCiDAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTIyMVoXDTI4\r\n"
        "MDIyNzE4MTIyMVowKzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEOMAwGA1UE\r\n"
        "AwwFYWxpY2UwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHTVvCanIFSZut43PlV\r\n"
        "qn6sjbwerVajKgDUq+Nuy7j+0SqiKr++BMJW98eoZWG/owiwt9aAyzsDJX+5KP+d\r\n"
        "Dm2lrQA/L+VrMHG2iCT8MJJeVIdPrvWpB6VI0/sk2KwGX487uoYi3zGig+1r66rx\r\n"
        "92Kjb/mKpvny2/Pl2nzCIsRNpM/ZdzAKBggqhkjOPQQDBAOBjAAwgYgCQgE4qJec\r\n"
        "oFoQy5hfgA19wkvisa38luQIi1xFe3gcfVQUKm3DpVFCPP0QG4dNBRkfEk1kcHUQ\r\n"
        "21MK6etDVF9OcrgHfwJCAOwAVgG32RUs9St9FwaHq5uo6zfMfhlv3YDIXy9xarLs\r\n"
        "8OVMzYSmtPgAalMJ82I5G8w51aAKe3vu26DsW3xwicFm\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,80E3D2B4DDFFAEC7068A2C8D4A692A78\r\n"
        "\r\n"
        "U01MGhXfF4UPdC4hyMZgZTTQSUp26ut3oU5rGjH+Otf7BzAOpNvn3/v5dQ840WKY\r\n"
        "PqXZIMAJbh+w5QgSzMIKApgVcUNTYnVsgTq+Qy5xfq4zGJEi9Dgy3Rr+r9TqP42E\r\n"
        "arSYQUaJSbAcQutHWPxWDheUwMYRnVH4/K4kZY1VMioK6WgNk4bjZkMg7jV6balY\r\n"
        "NZ4pJaOXn0RbJgUt/ZVDy0R20ogkhRtU0UjMA48NTFMKxk4QnaKyrm0a3soGysGi\r\n"
        "sLTe6ku21uFb1oVHXKwtVKXo4/WkAMbEhDIBsm6Cvdc=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "alice"
    },
    {
        { (const uint8_t*)"bob", sizeof("bob") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIByjCCASwCCQCu4kaR9/HCiTAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTIyMVoXDTI4\r\n"
        "MDIyNzE4MTIyMVowKTELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEMMAoGA1UE\r\n"
        "AwwDYm9iMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAiKyjUV9s6XIMDNHjCOCV\r\n"
        "DGH1/+g6/s5v/I1aoS0ByEkbov0KN+7Q0CAYqjUoVDNpc8bP6TL3poH381Eesrfi\r\n"
        "YtwBLuanVUhBDWuhnYDBn9LVovCyVj5KxwT3PaglGx0lrumVpUguURIJAkE0XBLZ\r\n"
        "ZtP/6pUFV+DBE5qiLfNwqrN6wrkwCgYIKoZIzj0EAwQDgYsAMIGHAkFAV0X1KlbE\r\n"
        "gEDg+fKxgJ3Ofw1udO8XzycCaaD30Cyd/Zr4s1akEBgqwm3B8qiFQNbhSwz2J3mo\r\n"
        "omXyHa99+DD9qwJCAUFhaweiBtGUfTm3wxEnzLgt9/qBPGJeStSvghsi/nwWpQF4\r\n"
        "WbawwslWC7B2vwYIGgguvE3Q8Aw1lbSStuBPsry+\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,1090AC1106F32A859CC2F8EB37FE5CBD\r\n"
        "\r\n"
        "hdmCJzQpQqWfFxaZ+8mXcC5NuuPCjvDFKtrSHXzWFJCTwFvcSFR/C0SshhR0w+Ja\r\n"
        "osRFYV7EcQKeFXSocs4m3C66zPEz0fzfXDvd8BW3jDb77pscxJZKL59ca3brC9J0\r\n"
        "Sshfp5xX7nqhy9ewmuUvneX3dECFHH6GpUI1IHsNNSaf1GM1N3NW87Pu9Au7YmQo\r\n"
        "Vn9MWmB6ueLAkmxdOmGImIRPIExm2h2dSVYYgpTay0p9j41LW6U54J1lFNbGnGw5\r\n"
        "AfVqZjZqNT9eI9VcKqf2szsKvaJnymOsVQGbOGUfu9c=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "bob"
    },
    {
        { (const uint8_t*)"eve", sizeof("eve") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIByzCCASwCCQCu4kaR9/HCijAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTIyMVoXDTI4\r\n"
        "MDIyNzE4MTIyMVowKTELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEMMAoGA1UE\r\n"
        "AwwDZXZlMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA68jxzavheUkDThDt9srH\r\n"
        "5By4ia9EOXDLgS/EuZtMSnjGtyf/tMAJKJ0ordDVuCIJ2Q5sENKvESXV9bXEffqi\r\n"
        "tw4B/UblWRPXlTxx0Cy2XyVDloWWJCuX2StilJZLKvoMycsghJEXvrlxyd7EjpWl\r\n"
        "SVlUXXZwilsMO7ENlmSGglZRptIwCgYIKoZIzj0EAwQDgYwAMIGIAkIB0GuWyLbH\r\n"
        "BUs4nFhvHUMCxmdMVCDKZH0cB0GiHrVpR7ZYRL1ANJ3f4S9/tlJ82AAdyiVQAZIZ\r\n"
        "Ir4PXMwOtNH/f5UCQgGISIkMlfWVslw1fcuxmYs8+ctk+kp3Xky34Au5KKuu7oJ2\r\n"
        "AlUXsC0T+AM1N8+hM3Rh9fKlpU6qWkILPS+OtsI2dw==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,E5542E85610DAACBCC93862EAA34C921\r\n"
        "\r\n"
        "M0esr6Y6T1L7+JhCDV0zpbEnvPiGWkaXNNn78EuuCwENtYYai3JctwKZmnvEWCk4\r\n"
        "7Ix1SENOCIqhSPvccdieprrvP0VbVKXvfXzpw4D5XspyIyYYXG9Y/QC1LMc6ntQm\r\n"
        "z9hj5MQhVhdZmO1NrR9PZwSitmZQ4sFA2FZCYH45PuErKVmRYc+pWkRGNXjIBi/r\r\n"
        "ciM7x4X2PAexbvV/+bCAs7j175UmGHzia8/NnZXcl3T7Elr/W9zcv0egYb4Th4gI\r\n"
        "nqk166md5CNx00D3nPuhJ5oW9M/zhuFXYIGBZPEjGC4=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "eve"
    },
    {
        { (const uint8_t*)"trudy", sizeof("trudy") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBzTCCAS4CCQCu4kaR9/HCizAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTIyMVoXDTI4\r\n"
        "MDIyNzE4MTIyMVowKzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEOMAwGA1UE\r\n"
        "AwwFdHJ1ZHkwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAFEenWt9BdgovlQs9zm\r\n"
        "SO/Rg142jdG2TEmmlcpKDOd7teibHANtrR5yXbYg+x2wMcSaq6tG767P8p3pyEV3\r\n"
        "9x8rmgFLxeSFoUj+E5DonTkPJ49ZCccBrIEU/JMIRni9mbgsjrJuittfdmKaG3Bz\r\n"
        "SgRGecNd9xT+A/btesYsgy/Mmx/r5zAKBggqhkjOPQQDBAOBjAAwgYgCQgDz3oTr\r\n"
        "xIUofm4JWVRQsNABcrZ18q9h9OCC7+AA3GPHugAKfdnEKMjKaIwsPB0Nep/vAoQZ\r\n"
        "eQelFL6GUJbGM4BC7wJCAYnwfgo0AbFGt60rYiz9wz3ECTEpNpg8H034RYjzGIJw\r\n"
        "T0gYf3nTZPhA4VTT2+6Fdfo6p0LHXhe1GG/f8FydvKKq\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,B83050C9D1910E07798129701273EB74\r\n"
        "\r\n"
        "X2YqBXTetIRMByE7SC2gnfYqewke41S/oG3GHsvhhf1a/F/iFvUhUBFDzGhvClgr\r\n"
        "v7M2spK1tzz4ptmfzrj4B9BiTzQF7rL8RVs/x4kORCKs8S4We/K+49pva+a7x6G5\r\n"
        "i9Oc/OUsY8rpOMZ3Tuz8gBfwJadT8ttX5CK0ioRWX8u74dc9YFjuCrTJOwgTAqOG\r\n"
        "7KCsmyaPvFEcn71OD6JkSYc6F0NNYOuRJAullume6mARjsBG8g4w6tB7h4WQ9nu7\r\n"
        "yJ4Tr+QIaaCmAefwvNZTURvGkl8bjGQRk3v8/dcvzj0=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "trudy"
    },
    {
        { (const uint8_t*)"DPS Test Publisher", sizeof("DPS Test Publisher") - 1 },
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
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,F0004AF499EA7B8A7252B286E3274508\r\n"
        "\r\n"
        "M5Du62n9VNOQjomIiToNODHeUexM6/kd/BJv5htLIKK+IuWhbz7uKiDa1ULrxz5x\r\n"
        "KVEh6b0h3WjQ5Z+tlHGGedD4uarwWcUDaw9j2kTpaN33HuCmQAEgH7Lqtq4BnI4S\r\n"
        "7FDtpoXtMOWGBs/AhQlUXQE0lFENacZ3PLkbafHVzcm19hWZk19ANpZOPbRNgMdQ\r\n"
        "vPIAyubRAwG+M+wtCxoG9kvwA2TpriwTPb3HaTtefXcaxM8ijS/VQa5mFjphSeUn\r\n"
        "BcrDGodlTMw9klV0eJpmDKUrpiXqExhzCsS33jK9YuM=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "DPS Test Publisher"
    },
    {
        { (const uint8_t*)"DPS Test Subscriber", sizeof("DPS Test Subscriber") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIB2jCCATwCCQDtkL14u3NJRTAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n"
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r\n"
        "MDIyNzE4MTQzMlowOTELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEcMBoGA1UE\r\n"
        "AwwTRFBTIFRlc3QgU3Vic2NyaWJlcjCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE\r\n"
        "AdPlr3YCutvRP0agz6KRmVVY4HuzS5zmEaBzkTCSWFkhugDgwmMgszDCAD5maqe5\r\n"
        "nAHammIc/MSw1UK+JFLFzSffAB48lbymUgTtE41sXWx82gc6vwvU25DqnNxHgS0L\r\n"
        "K0bVQweaXa4toICC3SLZD0iRDI1jUqZPwDCkbpF9LyDDa181MAoGCCqGSM49BAME\r\n"
        "A4GLADCBhwJBP7gFuL3dePSkYG4LoBg1atH6+2xfJWg51ZV8diRXWIgRlC5u3kCQ\r\n"
        "R+AJhf+Slik1tMQePTB5OojwrRYjw40iEDoCQgE6rg0vAE2AZVLYfVsz01we+Rov\r\n"
        "L8bFbjmY7xtqNCqRgCP7Nb/DLED8ahqo+uI7tPx5EqxDWj0FdxewZnbnBorBug==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,65E2556079AC9649D58B8CC72AE4A43E\r\n"
        "\r\n"
        "qWEHBFDO16P65LBjQecIrcql5bWuUx2SO87Qgllm576xolusU+iTExRVENjtO3Nl\r\n"
        "Vil2EqdMX2KHdv9p282lW1Drl069SesP69LiOo0sMYJefWJZRSnbRL7e7tDTXuUz\r\n"
        "p038ythZg7Ho6UggO6cvy08JomqMuJtwpJ6RTTFAsQMsEqCF8m0e26EdxrFUpkrM\r\n"
        "imwGuJ3hGzJKTZYaqK8i17LK+m4W0FzXETXp+qDyp9LBuZTqBISJ7MH+LOnY4neZ\r\n"
        "a/F20EFCFwL47sfQlZMsOYHw140IS2+YOyzOD051Gbw=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "DPS Test Subscriber"
    },
    {
        { NULL, 0 }, NULL, NULL, NULL
    }
};
