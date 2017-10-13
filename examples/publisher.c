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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>

#define MAX_TOPICS 64
#define MAX_MSG_LEN 128
#define MAX_TOPIC_LEN 256

static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static int requestAck = DPS_FALSE;

static DPS_Publication* currentPub = NULL;

static DPS_Event* nodeDestroyed;

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
    "MIIC5TCCAc0CCQD24JFU+B9ZOjANBgkqhkiG9w0BAQsFADAxMQswCQYDVQQGEwJV\r\n"
    "UzEMMAoGA1UECgwDRFBTMRQwEgYDVQQDDAtEUFMgVGVzdCBDQTAeFw0xNzEwMTYy\r\n"
    "MjI1MjlaFw0yNzEwMTQyMjI1MjlaMDgxCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANE\r\n"
    "UFMxGzAZBgNVBAMMEkRQUyBUZXN0IFB1Ymxpc2hlcjCCASIwDQYJKoZIhvcNAQEB\r\n"
    "BQADggEPADCCAQoCggEBAK4EZtIHhpWa45EgmUVYEpckgfN9ODcSrX012vF6APCd\r\n"
    "GZ1Esxm6/QsLYxtyWLKUTDxR1hmpTgS8q0RH3ZUXq1Rn4Y/wHN8ROvT01C9lkKbI\r\n"
    "XGrOIBLjyqsAGMfRTB26bP6Tgy9/UOhPDMiYGQIp7WdnBhdCZ8/l+6fmbWdjsVXK\r\n"
    "IMgMDwMvaxXRcfxH+n8IT4QF/FqufqvbNHlPuaWA5ShjcHLucHeR315AAYMqRgRn\r\n"
    "vWr6f8L9PoWze6pVsV9e8qnCo2JmkP23XOXvGegcuN7U8jU+jgUVcYbU+43vHKJn\r\n"
    "XS9qsOO+t7/fqfB+i3KHyMnkxSaLaQi9Fvxlc7+LYEcCAwEAATANBgkqhkiG9w0B\r\n"
    "AQsFAAOCAQEACzVVeSEynb84zXe0qofx9hTf/oGtaDrDDdLJ+glXVhNBDS77hNYg\r\n"
    "dXFjKhrucDbidv/HqXgayU8G3djqpYCfxCOECEOxc+T0I9yuXKZpOldX/Jc58v29\r\n"
    "d7W+I3gwtWiSwwxrHgXuewzKqZAjjHIQWGQT0hkPwJwYgbceNl0bzke4oYZ5aXfD\r\n"
    "RA48Bib0nW81jiGNoZKEIeELo1+cBUImk2NcQf5jO59UTeNLNaJTRO2ndTa+Tj8N\r\n"
    "VGmppeCvcTUaE0JR43jZSIpSuQaJf6mLehI5y/p2GfTPVOXgc2vlhnU7gjQgaskY\r\n"
    "70PEIZinT6jZ5fn14OAeuOLHc8EdS+gwEA==\r\n"
    "-----END CERTIFICATE-----\r\n";
static const char privateKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "Proc-Type: 4,ENCRYPTED\r\n"
    "DEK-Info: AES-256-CBC,E71AAF9E14492B8BEDEE1A044DE88B42\r\n"
    "\r\n"
    "1Y2jQ8Sy/Y9WUsoupIxjp5KIFG17RVNVE2+1FTL06SXqyCherjfytonCaf6ZH43A\r\n"
    "TNnrCPxZvf3c47N63My54BvGbd4a0m7pUuSQY/DBzdOMKiE3oqtBKS7f8Sg59NIp\r\n"
    "wXBX7GMsfBXxuESktYN2QTSQOoMQiXBt51J+DYxmRkPPdKAn0Medj/QGtDV7ud/O\r\n"
    "B9m/4KQ0cgxtR2DHSPDjHqP4foCojEYqwUtRbo/YVQiPP9zEu0e4Wn3Dpz5bqhl3\r\n"
    "Mt1bNZ7ZVBAoiTh3/UKs5nFYAvo0G9vSdpL3jhAdKfJYMbZQi6WMMB8gQC+NiULW\r\n"
    "P6BU0OVyw91A2FrqZPyNQBxA/E3xHgOg2grDIoQWMnoZZIY+aUn8x3ApmxeU1F08\r\n"
    "POe+UHj04dcKm2SEO2nibuk8jg9wImhBHjifA2ENaC6ALPH21L2akw2jKet3YpjN\r\n"
    "Q6bEJbrJ8f48e2TeOllJciKNgxiJKKKQChwClwMtPg0iqQPQDAJzAq+DS1wOWFuo\r\n"
    "V8iKJaUNcH3KDfP/Djdz8/mgDjkpKEnXwhjUWN0tZyrFSbzi09+6iNM+BOB7ohSj\r\n"
    "fuMG/xw6laBBPtfZ7NOnqlSO4rTmTHdkTU89US2SpltYRDxCsoHQRCVjg3lsTY54\r\n"
    "ibnwFR+JHU9Wn2/id/t7gMK1TZviiMRAFVZ/12cQ1/5/h6TIgSeLN5kq5V3XdirO\r\n"
    "A8GW5fmW0i7dcl7C6zOBTPED4/CnM5JOcHvJPQ0IuXcwaqWWABBdz51GHJ2eSZbD\r\n"
    "uSAoiT2iXJgjUma0klnPQNkqpI2lM/5vyw6MieN4whbh0SAhLuu/DeFuA9FLizjD\r\n"
    "swqM0enPuSJx4rPiNuhLqUM/De4VSxf9Lv+lcXfMdnTckoUREJia6lLbIXHVEgpp\r\n"
    "EAihvd+Xh0Q9pI6BzXkpg5UKQwhZx4zGUtEDsc7sj+k3Mm/FNVd10hfaGD167rAE\r\n"
    "c+uOk804PDPrfX5HpOnXnZ47UdzDJYc98ZBqM2Qdvq2UtvPSMuaBf9/7RkPPzN6Q\r\n"
    "5d2Q8i6fsjW0y26rVP11cAjH4LCQ1VmqSi9ng1u5q+6tKv7EsKd9K2f467XhrFfH\r\n"
    "t3k86i1echU0J4Cl6pJIhuPHYB4/YHOwjmQbCxA8k3GVuMg8Z+rPnRb7weeiA3uL\r\n"
    "81wtC5zmZD+MGoA4PV7+TpUHvXTya34KKJtHrE89WKw10NbgbJ9bf5M3BsJtpLws\r\n"
    "VJeiavBAjB1gYHqZII/AL1kEJBcZvmN3UV82MwbtmVhq+IguxerROZhG4gLgEuSh\r\n"
    "n3X4xKJDyN1FR0vX8VxQ/DrF0kcDxvHPtALUdLrcDnjBXVzLOmKfNYGpDAUGqhy5\r\n"
    "6cTRzgFvcVoovrfahl8NvzBWv5B+C+E0/zUV9zFGdeZQQGZ2efaVv58YPmt6vEj3\r\n"
    "afR8qAIbpx1fGKUNBk5LhcUeqp9rlhY/tGNcoGgHFfzdLAv3M+7jGXfjDjNu/vFR\r\n"
    "QDmGBzl4xNTxCULy4vHGOR8tnNd87SB++DgayHiKJM1k+Kmo5jV2tUVWu8dfLp+r\r\n"
    "Ee6ppjZXd4ClR9qcnKNzSDY4P9qJ0xvwUXfms0plpChNfj08FOadS8HL2lmo+ZZE\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";
static const char* password = "DPS Test Publisher";

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent(nodeDestroyed, DPS_OK);
}

static int AddTopics(char* topicList, char** msg, int* keep, int* ttl, int* encrypt)
{
    size_t i;

    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
    }
    *msg = NULL;
    *keep = 1;
    *ttl = 0;
    *encrypt = 1;
    numTopics = 0;
    while (numTopics < MAX_TOPICS) {
        size_t len = strcspn(topicList, " ");
        if (!len) {
            len = strnlen(topicList, MAX_TOPIC_LEN + 1);
            if (len > MAX_TOPIC_LEN) {
                return 0;
            }
        }
        if (topicList[0] == '-') {
            switch(topicList[1]) {
            case 't':
                if (!sscanf(topicList, "-t %d", ttl) || *ttl <= 0) {
                    DPS_PRINT("-t requires a positive integer\n");
                    return 0;
                }
                topicList += 3;
                break;
            case 'x':
                if (!sscanf(topicList, "-x %d", encrypt) || (*encrypt != 0 && *encrypt != 1)) {
                    DPS_PRINT("-x requires 1 or 0\n");
                    return 0;
                }
                topicList += 3;
                *keep = 0;
                break;
            case 'm':
                /*
                 * After "-m" the rest of the line is a message
                 */
                *msg = topicList + 1 + len;
                return 1;
            default:
                DPS_PRINT("Send one publication.\n");
                DPS_PRINT("  [topic1 ... topicN  [-x 0/1]] [-t <ttl>] [-m message]\n");
                DPS_PRINT("        -h: Print this message\n");
                DPS_PRINT("        -t: Set ttl on the publication\n");
                DPS_PRINT("        -x: Enable or disable encryption for this publication.\n\n");
                DPS_PRINT("        -m: Everything after the -m is the payload for the publication.\n\n");
                DPS_PRINT("  If there are no topic strings sends previous publication with a new sequence number\n");
                return 0;
            }
            len = strcspn(topicList, " ");
            if (!len) {
                return 0;
            }
        } else {
            if (len) {
                *keep = 0;
                topics[numTopics] = malloc(len + 1);
                memcpy(topics[numTopics], topicList, len);
                topics[numTopics][len] = 0;
                ++numTopics;
                if (!topicList[len]) {
                    break;
                }
            }
        }
        topicList += len + 1;
    }
    return 1;
}

static void OnAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_PRINT("Ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), DPS_PublicationGetSequenceNum(pub));
    if (len) {
        DPS_PRINT("    %.*s\n", (int)len, data);
    }
}

static void ReadStdin(DPS_Node* node)
{
    char lineBuf[MAX_TOPIC_LEN + 1];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != NULL) {
        size_t len = strnlen(lineBuf, sizeof(lineBuf));
        int ttl;
        int keep;
        int encrypt;
        char* msg = NULL;
        DPS_Status ret;

        while (len && isspace(lineBuf[len - 1])) {
            --len;
        }
        if (len) {
            lineBuf[len] = 0;
            DPS_PRINT("Pub: %s\n", lineBuf);
            if (!AddTopics(lineBuf, &msg, &keep, &ttl, &encrypt)) {
                continue;
            }
        } else if (currentPub) {
            keep = 1;
        } else {
            /*
             * Force the usage message to be printed
             */
            AddTopics("-h", &msg, &keep, &ttl, &encrypt);
            continue;
        }
        if (!keep) {
            DPS_DestroyPublication(currentPub);
            currentPub = DPS_CreatePublication(node);
            ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, encrypt ? &keyId[1] : NULL, requestAck ? OnAck : NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
                break;
            }
        }
        ret = DPS_Publish(currentPub, msg, msg ? strnlen(msg, MAX_MSG_LEN) : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)), DPS_PublicationGetSequenceNum(currentPub));
        } else {
            DPS_ERRPRINT("Failed to publish %s error=%s\n", lineBuf, DPS_ErrTxt(ret));
            break;
        }
    }
    DPS_DestroyNode(node, OnNodeDestroyed, NULL);
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

#define MAX_LINKS  8

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    const DPS_UUID* nodeKeyId = NULL;
    DPS_Node* node;
    char** arg = argv + 1;
    const char* host = NULL;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int numLinks = 0;
    int wait = 0;
    int encrypt = DPS_TRUE;
    int ttl = 0;
    int subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
    int i;
    char* msg = NULL;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;
    int listenPort = 0;
    DPS_NodeAddress* addr = NULL;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-p", &arg, &argc, &linkPort[numLinks], 1, UINT16_MAX)) {
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
        if (strcmp(*arg, "-m") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            msg = *arg++;
            continue;
        }
        if (IntArg("-l", &arg, &argc, &listenPort, 1000, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-w", &arg, &argc, &wait, 0, 30)) {
            continue;
        }
        if (IntArg("-t", &arg, &argc, &ttl, 0, 2000)) {
            continue;
        }
        if (IntArg("-r", &arg, &argc, &subsRate, 0, INT32_MAX)) {
            continue;
        }
        if (IntArg("-x", &arg, &argc, &encrypt, 0, 1)) {
            continue;
        }
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            requestAck = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topics)) {
            DPS_PRINT("Too many topics - increase limit and recompile\n");
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }
    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (numLinks) {
        mcast = DPS_MCAST_PUB_DISABLED;
        addr = DPS_CreateAddress();
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

    ret = DPS_StartNode(node, mcast, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node, linkHosts[i], linkPort[i], addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
        }
    }

    nodeDestroyed = DPS_CreateEvent();

    if (numTopics) {
        currentPub = DPS_CreatePublication(node);

        ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, encrypt ? &keyId[1] : NULL, requestAck ? OnAck : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%s\n", DPS_ErrTxt(ret));
            return 1;
        }

        if (wait) {
            /*
             * Wait for a while before sending a publication
             */
            DPS_TimedWaitForEvent(nodeDestroyed, wait * 1000);
        }

        ret = DPS_Publish(currentPub, msg, msg ? strnlen(msg, MAX_MSG_LEN) + 1 : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)));
        } else {
            DPS_ERRPRINT("Failed to publish topics - error=%s\n", DPS_ErrTxt(ret));
        }
        /*
         * A brief delay before exiting to ensure the publication
         * gets sent and we have a chance to receive acks if requested
         */
        DPS_TimedWaitForEvent(nodeDestroyed, requestAck ? 2000 : 500);
        if (addr) {
            DPS_UnlinkFrom(node, addr);
            DPS_DestroyAddress(addr);
        }
        if (listenPort) {
            DPS_PRINT("Waiting for remote to link\n");
            DPS_TimedWaitForEvent(nodeDestroyed, 60 * 1000);
        }
        DPS_DestroyNode(node, OnNodeDestroyed, NULL);
    } else {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(node);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-x 0/1] [-a] [-w <seconds>] <seconds>] [-t <ttl>] [[-h <hostname>] -p <portnum>] [-l <portnum>] [-m <message>] [-r <milliseconds>] [topic1 topic2 ... topicN]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -x: Enable or disable encryption. Default is encryption enabled.\n");
    DPS_PRINT("       -a: Request an acknowledgement\n");
    DPS_PRINT("       -t: Set a time-to-live on a publication\n");
    DPS_PRINT("       -w: Time to wait between linking to remote node and sending publication\n");
    DPS_PRINT("       -l: Port number to listen on for incoming connections\n");
    DPS_PRINT("       -h: Specifies host (localhost is default). Mutiple -h options are permitted.\n");
    DPS_PRINT("       -p: port to link. Multiple -p options are permitted.\n");
    DPS_PRINT("       -m: A payload message to accompany the publication.\n\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n\n");
    DPS_PRINT("           Enters interactive mode if there are no topic strings on the command line.\n");
    DPS_PRINT("           In interactive mode type -h for commands.\n");
    return 1;
}


