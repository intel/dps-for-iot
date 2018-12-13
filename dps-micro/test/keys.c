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

#include "keys.h"

const DPS_KeyId NetworkKeyId = {
    { 0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26 },
    16
};

const DPS_Key NetworkKey = {
    DPS_KEY_SYMMETRIC,
    .symmetric = {
        { 0xcd,0xfe,0x31,0x59,0x70,0x5f,0xe4,0xc8,0xcb,0x40,0xac,0x69,0x9c,0x06,0x3a,0x1d },
        16
    }
};

static const uint8_t _Psk[NUM_KEYS][16] = {
    { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
    { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 }
};

const DPS_KeyId PskId[NUM_KEYS] = {
    {
        { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 },
        16
    },
    {
        { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc },
        16
    }
};

const DPS_Key Psk[NUM_KEYS] = {
    { DPS_KEY_SYMMETRIC,
        .symmetric = {
            { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
            16
        }
    },
    { DPS_KEY_SYMMETRIC,
        .symmetric = {
            { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 },
            16
        }
    }
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
        { "alice", sizeof("alice") - 1 },
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
        { "bob", sizeof("bob") - 1 },
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
        { "eve", sizeof("eve") - 1 },
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
        { "trudy", sizeof("trudy") - 1 },
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
        { "DPS Test Publisher", sizeof("DPS Test Publisher") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBiDCCAS0CCQCzbzjgbS2buTAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEwNTE3NDIyNVoXDTI4MDEwMzE3NDIyNVowTzELMAkG\r\n"
        "A1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEMMAoGA1UECgwDRFBTMRsw\r\n"
        "GQYDVQQDDBJEUFMgVGVzdCBQdWJsaXNoZXIwWTATBgcqhkjOPQIBBggqhkjOPQMB\r\n"
        "BwNCAAT9zFcF+A/Hp8mD4DZSUrbmbyQlj81LjGm7o7IBqF4mjlV7sgNtyAFvQYI7\r\n"
        "3BJYbcR15byhqNYT7oM6i4WvPCH0MAoGCCqGSM49BAMCA0kAMEYCIQCX7IHcB54O\r\n"
        "VBD7MQwf6aoKDHrLBA2oAk60Stxcfx5RdAIhAL3Dwkrz9BTjK7YbUPScMBUPO/8k\r\n"
        "68kLmXJncgz0HCAl\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,1015081BA68E2CFF939DD7F15415B0A8\r\n"
        "\r\n"
        "Fqu58/SuC8tFL5gpje6JI+Raq9DiCo/xWu32RzHastU20xie/8xO5ts+aLXQHPO+\r\n"
        "y/mogXxVnkfLBelgz3BhxitMOM2jEm3P8BwXzDWvm3BK5AneUaQMROHTMzU/pDlD\r\n"
        "DFcbIyQqLTFp0QLrvzplZWsFBAKXLs2bxcuyqRv4+h4=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "DPS Test Publisher"
    },
    {
        { "DPS Test Subscriber", sizeof("DPS Test Subscriber") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBiTCCAS4CCQCzbzjgbS2bujAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEwNTE3NDI0NloXDTI4MDEwMzE3NDI0NlowUDELMAkG\r\n"
        "A1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEMMAoGA1UECgwDRFBTMRww\r\n"
        "GgYDVQQDDBNEUFMgVGVzdCBTdWJzY3JpYmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0D\r\n"
        "AQcDQgAEbrDkznbJynaPPfKnnkx14nLX782a2SiPZHYFrDseHwoLOqWe6TI2bcIm\r\n"
        "rPEDasOnc8fywObXDwEKyRgIR1gqLDAKBggqhkjOPQQDAgNJADBGAiEAj7V5KV3y\r\n"
        "SwVLhWGC4tey6zs7G+IQMNPQF0A/+Ic1hLICIQD7TumHocAG2SG42IE4WcwllrBG\r\n"
        "LmXKOg4TBaBxS5GrDg==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,7F349D976187178514F51358734287B2\r\n"
        "\r\n"
        "uc2MV05GoQf5WKC62U1n5dX9O11OehzpxKVKQiiMoqB+PnkyFR8+eS/CLdhtHPC9\r\n"
        "cU6HJDaPdUFZlV0L+Dhl3L1vm0zBvRpIZUivZGzB3h6RMptvhoZ5rey1f1Kyq7oj\r\n"
        "1rEBHuMR4LT4PCrDQ4DpvOvAiJGpPMEaEovKhy+IneQ=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "DPS Test Subscriber"
    }
};
