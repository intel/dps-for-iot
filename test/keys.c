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

static const DPS_UUID _NetworkKeyId = {
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
};
static const uint8_t _NetworkKey[16] = {
    0xcd,0xfe,0x31,0x59,0x70,0x5f,0xe4,0xc8,0xcb,0x40,0xac,0x69,0x9c,0x06,0x3a,0x1d
};
const DPS_KeyId NetworkKeyId = { _NetworkKeyId.val, sizeof(_NetworkKeyId.val) };
const DPS_Key NetworkKey = { DPS_KEY_SYMMETRIC, .symmetric = { _NetworkKey, sizeof(_NetworkKey) } };

static const DPS_UUID _PskId[NUM_KEYS] = {
    { .val = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 } },
    { .val = { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc } }
};
static const uint8_t _Psk[NUM_KEYS][16] = {
    { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
    { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 }
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
    "MIIB1jCCAX2gAwIBAgIJALRXvI4W22jOMAoGCCqGSM49BAMCMEgxCzAJBgNVBAYT\r\n"
    "AlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxDDAKBgNVBAoMA0RQUzEUMBIGA1UE\r\n"
    "AwwLRFBTIFRlc3QgQ0EwHhcNMTgwMTA1MTc0MjAwWhcNMjgwMTAzMTc0MjAwWjBI\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANE\r\n"
    "UFMxFDASBgNVBAMMC0RQUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\r\n"
    "QgAE1c0x+gXvDcKjqOPOzGOu+C4u3YGvPoex0ZDqpcvp0q/S3cvUmzoZp7Q+yZpu\r\n"
    "2uR37hWCi8/87+JlYBO5Pqb6E6NQME4wHQYDVR0OBBYEFFTsOv15WFWhHgST28JS\r\n"
    "SbbnUdJ7MB8GA1UdIwQYMBaAFFTsOv15WFWhHgST28JSSbbnUdJ7MAwGA1UdEwQF\r\n"
    "MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgR4LKUEdYIaMMzBTDXfI2E/PZ2xKfBpei\r\n"
    "Wu+a8mdVTg4CIHXjJbMxosMAruzdFtf9Ik0bKfhFoXfr6XfFVsVxcU9l\r\n"
    "-----END CERTIFICATE-----\r\n";

const Id Ids[] = {
    {
        { (const uint8_t*)"alice", sizeof("alice") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBYzCCAQkCCQCzbzjgbS2cBDAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEzMTE4MDgzNloXDTI4MDEyOTE4MDgzNlowKzELMAkG\r\n"
        "A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEOMAwGA1UEAwwFYWxpY2UwWTATBgcqhkjO\r\n"
        "PQIBBggqhkjOPQMBBwNCAARWSwlhcDkArrgxtboT6/coO5YekTICt5Jsl4evVN42\r\n"
        "T5DX7bUmiR2t5H7ArZlzPTVJRWf4MDQUWPlKpxC5+hB8MAoGCCqGSM49BAMCA0gA\r\n"
        "MEUCIC592TJVkzPoQZbjihfhoxTRyvqdicCxdynIFSckuRTHAiEAoOliDzWga7p2\r\n"
        "n2izhnuKBU6gn+9J6+2AMeQuZbBs2HI=\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,1DDAEABA4ECA61D6FFF9BA91E4FCA678\r\n"
        "\r\n"
        "s78tXfhI9DHev8PsLt8TbpWTeMaWbg+WfLouT16VSjlEa/BxNZXZmcbLNQJDirrS\r\n"
        "Bu6GR2Dlh7cx2NSRR4L56ldRZM+Kliz8j4WQBHH3rpvX2i0YWaG9A0pDcbOtS8k9\r\n"
        "u1L413bDmtHdHMRAPvGVq/K5KY7osFLMHJzG7UWtC2w=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "alice"
    },
    {
        { (const uint8_t*)"bob", sizeof("bob") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBYjCCAQcCCQCzbzjgbS2cBTAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEzMTE4MDgzNloXDTI4MDEyOTE4MDgzNlowKTELMAkG\r\n"
        "A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEMMAoGA1UEAwwDYm9iMFkwEwYHKoZIzj0C\r\n"
        "AQYIKoZIzj0DAQcDQgAEjs5tbTLQHvdz0exFUX8/jFufixb1hG+ctkCikW1zKFpT\r\n"
        "doEPZGQ/QIL/0G7j53ZgyD+Ym0zeUbVwnZIJyOx5KzAKBggqhkjOPQQDAgNJADBG\r\n"
        "AiEAjUPZX2Bp/N5oGounu2fi/Hw73TwgfwXwmE3hSg2FxFcCIQDrptf4EUuHe+MP\r\n"
        "JwqC5ysmZRhdyUGmlFE9wFcaViMM4w==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,D0E58BC6B403768675587712ED20447E\r\n"
        "\r\n"
        "6hkZev34BDzdOo3qaTQpTsFeQc86zXBV99m0LYpojXmYx81mwXBzNTweV+XbwK9v\r\n"
        "289SJGs01Gq0H9uL79edR1uwEKSye0OMKiR5Gy46DFXYneBMVVrK/6TgQwPq35W0\r\n"
        "z0wO+AYpRbdvXUkJJE4sK+tuVeCPpfg6z5hAnq35hcI=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "bob"
    },
    {
        { (const uint8_t*)"eve", sizeof("eve") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBYjCCAQcCCQCzbzjgbS2cBjAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEzMTE4MDgzNloXDTI4MDEyOTE4MDgzNlowKTELMAkG\r\n"
        "A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEMMAoGA1UEAwwDZXZlMFkwEwYHKoZIzj0C\r\n"
        "AQYIKoZIzj0DAQcDQgAEL/rftnvMRbadGtB836rPqBWBIZ1Jj2CDj5tVbxrqE+XS\r\n"
        "8MJVvEMXuepE6IqvbAdtemHHZbEo/XA1YtOehvNfXzAKBggqhkjOPQQDAgNJADBG\r\n"
        "AiEAq7qkdvIiBRbuxt2OhCM8JAuxIFNizDWOwrhs1BvLcAsCIQCTqc9j3nfg7Fe4\r\n"
        "tqL6SHP13wYzaHFkAcx8cpbIfxtU2g==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,30E70C18B34A513D2B3D28B96E8C3ECB\r\n"
        "\r\n"
        "t2ywX2tbNw3fLMl2pa/lbf45RHecGQPDcVUCzrhro/JGq9xKpXLoWLwwa+sYrpVv\r\n"
        "5W9tYSx3oCehrm8Pq44dv65JIb39Vy1OAhcsczbQRFZ6uh7mp+YH1zj3+juQhqRS\r\n"
        "LjmOu0vJBPTnuEeN5hlXrPuymU9cez1RQBwu8vRoquY=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "eve"
    },
    {
        { (const uint8_t*)"trudy", sizeof("trudy") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBYzCCAQkCCQCzbzjgbS2cBzAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEzMTE4MDgzNloXDTI4MDEyOTE4MDgzNlowKzELMAkG\r\n"
        "A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEOMAwGA1UEAwwFdHJ1ZHkwWTATBgcqhkjO\r\n"
        "PQIBBggqhkjOPQMBBwNCAATxtnVcKFYOE8KuAT/GpTe7C4xcjPLM/HD9bZ62cFA7\r\n"
        "eDrrLUV3GSh6ZQH0o8+bIisEXxElwD9AyCbfc5rTXLPaMAoGCCqGSM49BAMCA0gA\r\n"
        "MEUCIQC97p99h23R686Vv37DSgcFrdKcMbneXnxrJQiSwCdL4wIgDEtGAoptwpqi\r\n"
        "Cf7N//U4ttUfghfr+pQMyCDI0XkbGJk=\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,2F3AF19B8633A6F6DB8A4017A0ADB449\r\n"
        "\r\n"
        "cFtQdTFzfJqa5uXyoOEdIe6EjCN3J3/bt8b3gJPPC2BBehcL3Q5qZItfdnB+R/Qq\r\n"
        "ROg8pmcA4LBzCVqK5AMaaK45sviqiOvdo+4oCIQMnLAQxATIvQKfmYmJImb8SIHq\r\n"
        "CTU3rrbzthxlUF/JeFSI/8vf7n1dOTO8cZbIZAZegnE=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "trudy"
    },
    {
        { (const uint8_t*)"DPS Test Publisher", sizeof("DPS Test Publisher") - 1 },
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
        { (const uint8_t*)"DPS Test Subscriber", sizeof("DPS Test Subscriber") - 1 },
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
    },
    {
        { NULL, 0 }, NULL, NULL, NULL
    }
};
