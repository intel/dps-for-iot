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

/*
 * Preshared keys for testing only - DO NOT USE THESE KEYS IN A REAL APPLICATION!!!!
 */
static uint8_t keyData[NUM_KEYS][16] = {
    { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 },
    { 0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98 }
};

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
        DPS_SetNetworkKey(memoryKeyStore, "test", 4);
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
