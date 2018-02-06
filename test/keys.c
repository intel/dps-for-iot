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
        { (const uint8_t*)"trent", sizeof("trent") - 1 },
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIBYjCCAQkCCQCzbzjgbS2cCTAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n"
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n"
        "UyBUZXN0IENBMB4XDTE4MDEzMTE4MDgzNloXDTI4MDEyOTE4MDgzNlowKzELMAkG\r\n"
        "A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEOMAwGA1UEAwwFdHJlbnQwWTATBgcqhkjO\r\n"
        "PQIBBggqhkjOPQMBBwNCAAReWKdbFiJ8korWEc+BAVlPGRLm66k7bJnCpR6djov+\r\n"
        "V99hhcloRqEk43L9bhEWzbHcUrLMJ7FOGF4yBc1cmt8qMAoGCCqGSM49BAMCA0cA\r\n"
        "MEQCICOq3MXs9w878Fyru5jfyuF1v2sIxnpxnS8zZOn8qQ8rAiANeAX0J3HezWYp\r\n"
        "cCXvRe81VtP8pGAT11jIJmBz5p9OKg==\r\n"
        "-----END CERTIFICATE-----\r\n",
        "-----BEGIN EC PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: AES-256-CBC,CFA02F5AE81ECA40A6A22215A77CB00A\r\n"
        "\r\n"
        "NLAt58sFSZFYNBtmBtEXEj9yTrivS3dnl5CG/LuXP9miZnWvo+rLBce2GHxIIlYg\r\n"
        "/qL72bna9GwFdiEKdV5dOLeMZr4A48C9RF0hzF7Px7F5W/3AejvFyoXSFfGi3gwe\r\n"
        "ZTtT4jMoE4wVrO/UPG5v6valRDeq6h5lvH4bZM5cbZM=\r\n"
        "-----END EC PRIVATE KEY-----\r\n",
        "trent"
    },
    {
        { NULL, 0 }, NULL, NULL, NULL
    }
};
