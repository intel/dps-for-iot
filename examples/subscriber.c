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

#include <assert.h>
#include <ctype.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>

static int quiet = DPS_FALSE;

static uint8_t AckFmt[] = "This is an ACK from %d";

#define NUM_KEYS 2

static DPS_UUID keyId[NUM_KEYS] = {
    { .val = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 } },
    { .val = { 0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc } }
};
static DPS_UUID networkKeyId = {
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
};

/*
 * Preshared keys for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */
static uint8_t keyData[NUM_KEYS][16] = {
    { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
    { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 }
};
static uint8_t networkKey[16] = {
    0xcd,0xfe,0x31,0x59,0x70,0x5f,0xe4,0xc8,0xcb,0x40,0xac,0x69,0x9c,0x06,0x3a,0x1d
};

/*
 * Certificates for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */
static const char trustedCAs[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDNTCCAh2gAwIBAgIJAOOE/gToCIERMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNV\r\n"
    "BAYTAlVTMQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQUyBUZXN0IENBMB4XDTE3\r\n"
    "MTAxNjIyMTUzNFoXDTI3MTAxNDIyMTUzNFowMTELMAkGA1UEBhMCVVMxDDAKBgNV\r\n"
    "BAoMA0RQUzEUMBIGA1UEAwwLRFBTIFRlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA\r\n"
    "A4IBDwAwggEKAoIBAQC9EITpHdKwziyaKeYzAdevxlXYpJhSJY/et9jcReJObAJ+\r\n"
    "mYV574RhmpJapQ/g0/aISu/KIIEXiDRIVluKUfm9CAkAqm8jWn7ARPL80ANeNhMs\r\n"
    "SEiYfv0r+YQFl2f+pMLArQuh0sMm8KSM+zX3t5w35SVD5T764tsr77T1mZ++l6cq\r\n"
    "cngNtFyRQLYYMXVymWxQWt4imtfCRmGgcCH/LpK8wzlzUm8ONfT4p5Im1UghhHCy\r\n"
    "J0jDKBg+ytkIMB6I9FVvkjV1NAyrsikeanHN3C0vgzcQImAw2KitWLIlTcOmynWV\r\n"
    "Xc7M1nVcIb6JWkf1AoQ/oVj2hWIIOZ/IN3IIv4r5AgMBAAGjUDBOMB0GA1UdDgQW\r\n"
    "BBShvP2WS1iqkFItrDmmXVtCWYlCQzAfBgNVHSMEGDAWgBShvP2WS1iqkFItrDmm\r\n"
    "XVtCWYlCQzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQALL+aUabuo\r\n"
    "gvIAwBKF08daYB9kkW1qwBJQOV50pxw/hRv7UOuUFMNC4Q3Z7ig8IvwmEMavtnys\r\n"
    "Kmjfxi9jtYa2gUZUbeAfq4iQP3nlaUbcsK2RhkmJZcKZIKL14dQUTpJFrSMqe5lp\r\n"
    "zF6BFcswePk5w064WIfLKtsLgckzlOhEBYtO3EZFAk/1pUGg2RAOoPJM915Xkrcz\r\n"
    "Nn0O/QkUGCfgW8IQZMKCIPej/uGYCv5htTWwmm904gVTODEcBagzc9JdWxI6hKA6\r\n"
    "n9tWPxx0iSC3qcgT++SrbDt6VtAtoh97N2v848L2X7wdRrxokgfncvfzsxbYp/DY\r\n"
    "iwqVmHyLPIEZ\r\n"
    "-----END CERTIFICATE-----\r\n";
static const char cert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIC5jCCAc4CCQD24JFU+B9ZOzANBgkqhkiG9w0BAQsFADAxMQswCQYDVQQGEwJV\r\n"
    "UzEMMAoGA1UECgwDRFBTMRQwEgYDVQQDDAtEUFMgVGVzdCBDQTAeFw0xNzEwMTYy\r\n"
    "MjI2MzRaFw0yNzEwMTQyMjI2MzRaMDkxCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANE\r\n"
    "UFMxHDAaBgNVBAMME0RQUyBUZXN0IFN1YnNjcmliZXIwggEiMA0GCSqGSIb3DQEB\r\n"
    "AQUAA4IBDwAwggEKAoIBAQDOQOcueAC9YoawE7ir4xrv15Bqdegzdk3/9DMKjnpC\r\n"
    "+O0GEs+v19Gaxbz//Zan9qLmaNM2PZXHgHCv4dX2FoKBKo+ewAXINr1Ymq8J8pnH\r\n"
    "5R6XIX1ApCQP9BouOjYIQ0/KySuVindhH5w8Pcom+tvpHJz/P9DqCF/6VRUsv2IV\r\n"
    "hnU104niXxZKGKSsr17ysqIkTr548jxDLjt48McNy46QoQnYtxIbOW6O8eWqZknJ\r\n"
    "saTwV+Uvr0PyzdH5LtQyscXvnN8l6BOZsdfxyVy6jX2qAJUuT7l1FbC+hHcJQgsF\r\n"
    "BT+gFciRE9GLSPcmyYO8IxFW7zrJgxUyTlFTzd1C3SHRAgMBAAEwDQYJKoZIhvcN\r\n"
    "AQELBQADggEBAKLjPntzzEhPIubW3S4mSQ0Utg8nPQaf+u3FZqHKvYgqvPvwHnPN\r\n"
    "lj6cy3q0YOA9RAeoeOQTZXucC77pt2xLVinx4Rg4CQO4ZNscnZaD2bmLhOoWoKPR\r\n"
    "MEXXRBX02pR8nBITGprCOkpHxUBOWQQ4KaDVubFk/dRQn0/lpoc15dgPWr/cUXL+\r\n"
    "0qLinujKDGlHu7thZf6LhClQlhiej20NTQmxi0ZWB8QrdDkwsBKsKEW3JYfDEJ+X\r\n"
    "DuzNPCZM9YbY8K+C6gv656bXM3ejipYZkfwbgoeLKkhH0DB5ss3kB9vT1c83V8Ls\r\n"
    "SbJ/vaDQvFBRg6V1BQVGRweNnyxopxwU8+Q=\r\n"
    "-----END CERTIFICATE-----\r\n";
static const char privateKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "Proc-Type: 4,ENCRYPTED\r\n"
    "DEK-Info: AES-256-CBC,A06A7B6E50A8016E090337AC383079B7\r\n"
    "\r\n"
    "Xzbu/nmkL/IDZXzklaqNBUZCoQorjxpp8oG9PumA2/IsoVsi9NkcEk+hw0kyYAnV\r\n"
    "C9WygEOWlzwd0movMwajrTlLFGRZ9DSUH5YQ3vsMEcQy4jna05h4crC7VAJYhpBO\r\n"
    "gA0poudiTXQA2I3Zg/XPzBEvG6L76NCTxVpyMG3DuOv/GLBW0Tg5M8pz6drqvGf3\r\n"
    "YMUE92vmUi3AvtC1/wacQB54yPtKBXt6ncvy0Tx2TdPoajteME98PJGtrkYVyzAs\r\n"
    "lxzLld5VGT8XLUUSesmbjwCECI6z+Kq3+ZYQ3BGjhiH1lTIQeFM08+xRD7Lefvr0\r\n"
    "SCdX1LcmguwZIiVeLCmmsCwPZfIWkdZCgejs+dKTvDBtCk51vEgdmcJN9tAca3t9\r\n"
    "9Gyr1T/rNVrSdI9sFOzWBfbJ6XQgrasxTSLe9ynwLpYDYM/k/xOZJPTd/4ISieCE\r\n"
    "DRQTZsrJHRAfR5VH9xaRZevVUF45PzMlbfBGGCqq9P9TNPpSMJ6GnjF+2X8au600\r\n"
    "FJa/dZuTUbiXOVcZupKQ6KZGQlIF5Nm7BjKgZuJH4tbrHXqXpHAbw7a+yU1wmLmq\r\n"
    "1yQJa0xcpWea9co8GGk77ONZf8iI8T9aVtNRcOKY1v78SVc1FsQi/frLxQEW68xY\r\n"
    "ShNi7kEr9azf237pzf+As6lwWle/jt9IccdLJf8s7eMwX41k1AlOlNbvGabnPSrm\r\n"
    "QZnMQ7jx7hudgbBnestOLGhiMPXKHpNMBH1yBn9uMem91ZtcmBHg7UV8/rTD6jNu\r\n"
    "S52o0Ej8Kg5yNysssLA4uLEpEMJI6MhMQIhfdZTwuRYNZrKzr8BzO/gc7Q/YrETj\r\n"
    "G2HFXen24KZF54fBp7iytLlE8wNFRY+jhI8tpDYKTs6cIfitcHyFy6e0iCnqjfS2\r\n"
    "Qev7/coRAYotYYq7I91Cm1l76QsNj4wdovqz0zGEZAouok546joU1xH9vNVHHW07\r\n"
    "EJq98SlQHljbFD2F2QZPPLxkujUm7WoGLobxie+TZHlaG0PWDbih9a+eVlU5okxO\r\n"
    "/ZHgwv55hYO33xi3xNfV+AqMv6lVweSsGcLXMR/rWMy976TkBQMNaBlws6c+7fOh\r\n"
    "n/vKC2yR36YeK0fOZaGqSRH859y06pejTIKLDXnjrN/fKjKhKK9E82r+HoNqYdwg\r\n"
    "r2xK6SuSQY74JlJBKktIPBpla3FgwesJovWZcDb0PLJCAhlLN2Tm4arJSDzeG9l1\r\n"
    "7snRjXAYlzPshjkgWlXEKXv/idCovtfbzoRmtdoZloXsCMzbUkGGuBKnxetzukdH\r\n"
    "/Rf8humu6/6T7Q+skUSvI9Pm0Yt3fbtcDMGFS9+x+UHXmRj2mZh0dbhNzXJ+/1xu\r\n"
    "CQ9rq7UZJoKv6OmIPynrnRjY1jTqRzy80uFBcqxsPsA5B/uSZEy9iS9GRJ1/38ts\r\n"
    "ZFTeyBuVOyovQE4/1z6TkX8SuXEHr7m7qfZGXu3fIdAJ3IZ4BdlecmXgoPeY0fUO\r\n"
    "tPn+4wOq30d3q9HRrFm8mph4Szt6lFAkWjFesvLkM1l/CW39Xf+XTtnDVfQj/uDF\r\n"
    "PNvTdvmNRWZ1EaTxC/jsrks6dg5Da9eKehLvwoHKN6XOSiFQQqu88K5paxu4MEvR\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";
static const char* password = "DPS Test Subscriber";

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Status ret;
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t i;
    size_t numTopics;

    if (!quiet) {
        DPS_PRINT("Pub %s(%d) matches:\n", DPS_UUIDToString(pubId), sn);
        DPS_PRINT("  pub ");
        numTopics = DPS_PublicationGetNumTopics(pub);
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" | ");
            }
            DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
        }
        DPS_PRINT("\n");
        DPS_PRINT("  sub ");
        numTopics = DPS_SubscriptionGetNumTopics(sub);
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" & ");
            }
            DPS_PRINT("%s", DPS_SubscriptionGetTopic(sub, i));
        }
        DPS_PRINT("\n");
        if (data) {
            DPS_PRINT("%.*s\n", (int)len, data);
        }
    }
    if (DPS_PublicationIsAckRequested(pub)) {
        char ackMsg[sizeof(AckFmt) + 8];

        sprintf(ackMsg, AckFmt, DPS_GetPortNumber(DPS_PublicationGetNode(pub)));
        DPS_PRINT("Sending ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), DPS_PublicationGetSequenceNum(pub));
        DPS_PRINT("    %s\n", ackMsg);

        ret = DPS_AckPublication(pub, ackMsg, strnlen(ackMsg, sizeof(ackMsg)));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

#define MAX_TOPICS 64
#define MAX_TOPIC_LEN 256

static int IsInteractive()
{
#ifdef _WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(fileno(stdin));
#endif
}

static void ReadStdin(DPS_Node* node)
{
    char lineBuf[MAX_TOPIC_LEN + 1];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != NULL) {
        char* topics[MAX_TOPICS];
        size_t numTopics = 0;
        char* topicList;
        DPS_Subscription* subscription;
        DPS_Status ret;
        size_t len;
        size_t i;

        len = strnlen(lineBuf, sizeof(lineBuf));
        while (len && isspace(lineBuf[len - 1])) {
            --len;
        }
        if (len) {
            lineBuf[len] = 0;
            DPS_PRINT("Sub: %s\n", lineBuf);

            topicList = lineBuf;
            numTopics = 0;
            while (numTopics < MAX_TOPICS) {
                size_t len = strcspn(topicList, " ");
                if (!len) {
                    len = strlen(topicList);
                }
                if (!len) {
                    goto next;
                }
                topics[numTopics] = malloc(len + 1);
                memcpy(topics[numTopics], topicList, len);
                topics[numTopics][len] = 0;
                ++numTopics;
                if (!topicList[len]) {
                    break;
                }
                topicList += len + 1;
            }
        }
        if (numTopics) {
            subscription = DPS_CreateSubscription(node, (const char**)topics, numTopics);
            if (!subscription) {
                ret = DPS_ERR_RESOURCES;
                DPS_ERRPRINT("Failed to create subscription - error=%s\n", DPS_ErrTxt(ret));
                break;
            }
            ret = DPS_Subscribe(subscription, OnPubMatch);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to subscribe topics - error=%s\n", DPS_ErrTxt(ret));
                break;
            }
        }
    next:
        for (i = 0; i < numTopics; ++i) {
            free(topics[i]);
        }
    }
}

static int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return 0;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

#define MAX_LINKS 16

int main(int argc, char** argv)
{
    DPS_Status ret;
    char* topicList[64];
    char** arg = argv + 1;
    int numTopics = 0;
    int wait = 0;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    const DPS_UUID* nodeKeyId = NULL;
    DPS_Node* node;
    DPS_Event* nodeDestroyed = NULL;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = NULL;
    int encrypt = DPS_TRUE;
    int subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
    int listenPort = 0;
    int numLinks = 0;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int numAddrs = 0;
    DPS_NodeAddress* addrs[MAX_LINKS];

    DPS_Debug = 0;

    while (--argc) {
        /*
         * Topics must come last
         */
        if (numTopics == 0) {
            if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
                continue;
            }
            if (IntArg("-p", &arg, &argc, &linkPort[numLinks], 1, UINT16_MAX)) {
                if (numLinks == (MAX_LINKS - 1)) {
                    DPS_PRINT("Too many -p options\n");
                    goto Usage;
                }
                linkHosts[numLinks] = host;
                ++numLinks;
                continue;
            }
            if (strcmp(*arg, "-h") == 0) {
                ++arg;
                if (!--argc) {
                    goto Usage;
                }
                host = *arg++;
                continue;
            }
            if (strcmp(*arg, "-q") == 0) {
                ++arg;
                quiet = DPS_TRUE;
                continue;
            }
            if (IntArg("-w", &arg, &argc, &wait, 0, 30)) {
                continue;
            }
            if (IntArg("-x", &arg, &argc, &encrypt, 0, 1)) {
                continue;
            }
            if (IntArg("-r", &arg, &argc, &subsRate, 0, INT32_MAX)) {
                continue;
            }
            if (strcmp(*arg, "-m") == 0) {
                ++arg;
                mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
                continue;
            }
            if (strcmp(*arg, "-d") == 0) {
                ++arg;
                DPS_Debug = 1;
                continue;
            }
        }
        if (strcmp(*arg, "-s") == 0) {
            ++arg;
            /*
             * NULL separator between topic lists
             */
            if (numTopics > 0) {
                topicList[numTopics++] = NULL;
            }
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topicList)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", argv[0]);
            goto Usage;
        }
        topicList[numTopics++] = *arg++;
    }

    if (!numLinks) {
        mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
    }
    if (encrypt) {
        memoryKeyStore = DPS_CreateMemoryKeyStore();
        for (size_t i = 0; i < NUM_KEYS; ++i) {
            DPS_SetContentKey(memoryKeyStore, &keyId[i], keyData[i], 16);
        }
        nodeKeyId = &keyId[0];
        DPS_SetNetworkKey(memoryKeyStore, (const uint8_t*)&networkKeyId, sizeof(DPS_UUID), networkKey, 16);
        DPS_SetTrustedCA(memoryKeyStore, trustedCAs, sizeof(trustedCAs));
        DPS_SetCertificate(memoryKeyStore, cert, sizeof(cert), privateKey, sizeof(privateKey), password, strlen(password));
    }
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), nodeKeyId);
    DPS_SetNodeSubscriptionUpdateDelay(node, subsRate);

    ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(node));

    nodeDestroyed = DPS_CreateEvent();

    if (wait) {
        /*
         * Wait for a while before trying to link
         */
        DPS_TimedWaitForEvent(nodeDestroyed, wait * 1000);
    }

    if (numTopics) {
        char** topics = topicList;
        while (numTopics >= 0) {
            DPS_Subscription* subscription;
            int count = 0;
            while (count < numTopics) {
                if (!topics[count]) {
                    break;
                }
                ++count;
            }
            subscription = DPS_CreateSubscription(node, (const char**)topics, count);
            ret = DPS_Subscribe(subscription, OnPubMatch);
            if (ret != DPS_OK) {
                break;
            }
            topics += count + 1;
            numTopics -= count + 1;
        }
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
    }
    if (numLinks) {
        int i;
        for (i = 0; i < numLinks; ++i, ++numAddrs) {
            addrs[i] = DPS_CreateAddress();
            ret = DPS_LinkTo(node, linkHosts[i], linkPort[i], addrs[i]);
            if (ret != DPS_OK) {
                DPS_DestroyAddress(addrs[i]);
                DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
                goto Exit;
            }
        }
    }
    if (!numTopics && IsInteractive())
    {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(node);
        int i;
        for (i = 0; i < numAddrs; ++i) {
            DPS_Status unlinkRet = DPS_UnlinkFrom(node, addrs[i]);
            DPS_DestroyAddress(addrs[i]);
            if (unlinkRet != DPS_OK) {
                DPS_ERRPRINT("DPS_UnlinkFrom %s returned %s\n", DPS_NodeAddrToString(addrs[i]), DPS_ErrTxt(unlinkRet));
            }
        }
        DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    }

Exit:
    if (nodeDestroyed) {
        if (ret != DPS_OK) {
            DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
        }
        DPS_WaitForEvent(nodeDestroyed);
        DPS_DestroyEvent(nodeDestroyed);
    }
    if (memoryKeyStore) {
        DPS_DestroyMemoryKeyStore(memoryKeyStore);
    }
    return (ret == DPS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;

Usage:
    DPS_PRINT("Usage %s [-d] [-q] [-m] [-w <seconds>] [-x 0/1] [[-h <hostname>] -p <portnum>] [-l <listen port] [-m] [-r <milliseconds>] [[-s] topic1 ... topicN]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -q: Quiet - suppresses output about received publications.\n");
    DPS_PRINT("       -x: Enable or disable encryption. Default is encryption enabled.\n");
    DPS_PRINT("       -h: Specifies host (localhost is default). Mutiple -h options are permitted.\n");
    DPS_PRINT("       -w: Time to wait before establishing links\n");
    DPS_PRINT("       -p: A port to link. Multiple -p options are permitted.\n");
    DPS_PRINT("       -m: Enable multicast receive. Enabled by default is there are no -p options.\n");
    DPS_PRINT("       -l: port to listen on. Default is an ephemeral port.\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n\n");
    DPS_PRINT("       -s: list of subscription topic strings. Multiple -s options are permitted\n");
    return EXIT_FAILURE;
}
