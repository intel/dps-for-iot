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
#include <dps/json.h>
#include "keys.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

static int quiet = DPS_FALSE;
static int json = DPS_FALSE;

static const char AckFmt[] = "This is an ACK from %d";
static const char JSONAckFmt[] = "{\"msg\":\"ACK Message\",\"port\":%d}";

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    char jsonStr[1024];
    DPS_Status ret;
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    const DPS_KeyId* senderId = DPS_PublicationGetSenderKeyId(pub);
    size_t i;
    size_t numTopics;

    if (!quiet) {
        DPS_PRINT("Pub %s(%d) [%s] matches:\n", DPS_UUIDToString(pubId), sn, KeyIdToString(senderId));
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
            if (json) {
                ret = DPS_CBOR2JSON(data, len, jsonStr, sizeof(jsonStr), DPS_TRUE);
                if (ret == DPS_OK) {
                    DPS_PRINT("%s\n", jsonStr);
                }
            } else {
                DPS_PRINT("%.*s\n", (int)len, data);
            }
        }
    }
    if (DPS_PublicationIsAckRequested(pub)) {
        uint8_t ackMsg[64];
        size_t len;
        DPS_PRINT("Sending ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), DPS_PublicationGetSequenceNum(pub));
        if (json) {
            sprintf(jsonStr, JSONAckFmt, DPS_GetPortNumber(DPS_PublicationGetNode(pub)));
            DPS_PRINT("    %s\n", jsonStr);
            ret = DPS_JSON2CBOR(jsonStr, ackMsg, sizeof(ackMsg), &len);
            assert(ret == DPS_OK);
        } else {
            sprintf((char*)ackMsg, AckFmt, DPS_GetPortNumber(DPS_PublicationGetNode(pub)));
            DPS_PRINT("    %s\n", ackMsg);
            len = strnlen((char*)ackMsg, sizeof(ackMsg));
        }
        ret = DPS_AckPublication(pub, ackMsg, len);
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
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

typedef struct _Args {
    int numTopics;
    char* topicList[64];
    int listenPort;
    int numLinks;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int wait;
    int encrypt;
    int subsRate;
    int mcastPub;
    int interactive;
} Args;

typedef struct _Subscriber {
    DPS_Node* node;
    int numAddrs;
    DPS_NodeAddress* addrs[MAX_LINKS];
} Subscriber;

static int IsInteractive(Args* args)
{
    return args->interactive ||
        (!args->numTopics &&
#ifdef _WIN32
         _isatty(_fileno(stdin)));
#else
         isatty(fileno(stdin)));
#endif
}

static int ParseArgs(int argc, char** argv, Args* args)
{
    const char* host = NULL;

    memset(args, 0, sizeof(*args));
    args->encrypt = 1;
    args->subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
    args->mcastPub = DPS_MCAST_PUB_DISABLED;

    for (; argc; --argc) {
        /*
         * Topics must come last
         */
        if (args->numTopics == 0) {
            if (IntArg("-l", &argv, &argc, &args->listenPort, 1, UINT16_MAX)) {
                continue;
            }
            if (IntArg("-p", &argv, &argc, &args->linkPort[args->numLinks], 1, UINT16_MAX)) {
                if (args->numLinks == (MAX_LINKS - 1)) {
                    DPS_PRINT("Too many -p options\n");
                    return DPS_FALSE;
                }
                args->linkHosts[args->numLinks] = host;
                ++args->numLinks;
                continue;
            }
            if (strcmp(*argv, "-h") == 0) {
                ++argv;
                if (!--argc) {
                    return DPS_FALSE;
                }
                host = *argv++;
                continue;
            }
            if (strcmp(*argv, "-q") == 0) {
                ++argv;
                quiet = DPS_TRUE;
                continue;
            }
            if (IntArg("-w", &argv, &argc, &args->wait, 0, 30)) {
                continue;
            }
            if (IntArg("-x", &argv, &argc, &args->encrypt, 0, 3)) {
                continue;
            }
            if (IntArg("-r", &argv, &argc, &args->subsRate, 0, INT32_MAX)) {
                continue;
            }
            if (strcmp(*argv, "-m") == 0) {
                ++argv;
                args->mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
                continue;
            }
            if (strcmp(*argv, "-d") == 0) {
                ++argv;
                DPS_Debug = DPS_TRUE;
                continue;
            }
            if (strcmp(*argv, "-j") == 0) {
                ++argv;
                json = 1;
                continue;
            }
        }
        if (strcmp(*argv, "-s") == 0) {
            ++argv;
            /*
             * NULL separator between topic lists
             */
            if (args->numTopics > 0) {
                args->topicList[args->numTopics++] = NULL;
            }
            continue;
        }
        if (strcmp(*argv, "--") == 0) {
            /*
             * End of topics, use interactive mode
             */
            args->interactive = DPS_TRUE;
            return DPS_TRUE;
        }
        if (*argv[0] == '-') {
            return DPS_FALSE;
        }
        if (args->numTopics == A_SIZEOF(args->topicList)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", argv[0]);
            return DPS_FALSE;
        }
        args->topicList[args->numTopics++] = *argv++;
    }
    return DPS_TRUE;
}

static int Subscribe(Subscriber* subscriber, Args* args)
{
    DPS_Status ret = DPS_ERR_ARGS;

    if (args->numTopics) {
        char** topics = args->topicList;
        while (args->numTopics >= 0) {
            DPS_Subscription* subscription;
            int count = 0;
            while (count < args->numTopics) {
                if (!topics[count]) {
                    break;
                }
                ++count;
            }
            subscription = DPS_CreateSubscription(subscriber->node, (const char**)topics, count);
            ret = DPS_Subscribe(subscription, OnPubMatch);
            if (ret != DPS_OK) {
                break;
            }
            topics += count + 1;
            args->numTopics -= count + 1;
        }
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

static int LinkTo(Subscriber* subscriber, Args* args)
{
    DPS_Status ret;
    int i;

    if (args->numLinks) {
        for (i = 0; i < args->numLinks; ++i, ++subscriber->numAddrs) {
            subscriber->addrs[subscriber->numAddrs] = DPS_CreateAddress();
            ret = DPS_LinkTo(subscriber->node, args->linkHosts[i], args->linkPort[i],
                             subscriber->addrs[subscriber->numAddrs]);
            if (ret == DPS_OK) {
                DPS_PRINT("Subscriber is linked to %s\n",
                          DPS_NodeAddrToString(subscriber->addrs[subscriber->numAddrs]));
            } else {
                DPS_DestroyAddress(subscriber->addrs[subscriber->numAddrs]);
                DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", args->linkPort[i], DPS_ErrTxt(ret));
                return DPS_FALSE;
            }
        }
    }
    return DPS_TRUE;
}

static void UnlinkFrom(Subscriber* subscriber)
{
    int i;
    for (i = 0; i < subscriber->numAddrs; ++i) {
        DPS_Status unlinkRet = DPS_UnlinkFrom(subscriber->node, subscriber->addrs[i]);
        DPS_DestroyAddress(subscriber->addrs[i]);
        if (unlinkRet != DPS_OK) {
            DPS_ERRPRINT("DPS_UnlinkFrom %s returned %s\n", DPS_NodeAddrToString(subscriber->addrs[i]), DPS_ErrTxt(unlinkRet));
        }
    }
}

#define MAX_LINE_LEN 256
#define MAX_TOPICS 64
#define MAX_ARGS (32 + MAX_TOPICS)

static void ReadStdin(Subscriber* subscriber)
{
    char lineBuf[MAX_LINE_LEN + 1];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != NULL) {
        Args args;
        int argc = 0;
        char *argv[MAX_ARGS];
        size_t len = strnlen(lineBuf, sizeof(lineBuf));
        while (len && isspace(lineBuf[len - 1])) {
            --len;
        }
        if (len) {
            char* tok;
            lineBuf[len] = 0;
            for (tok = strtok(lineBuf, " "); tok && (argc < MAX_ARGS); tok = strtok(NULL, " ")) {
                argv[argc++] = tok;
            }
        }
        if (!ParseArgs(argc, argv, &args)) {
            continue;
        }
        Subscribe(subscriber, &args);
        LinkTo(subscriber, &args);
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    Args args;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    const DPS_KeyId* nodeKeyId = NULL;
    DPS_Event* nodeDestroyed = NULL;
    Subscriber subscriber;

    DPS_Debug = DPS_FALSE;
    memset(&subscriber, 0, sizeof(subscriber));

    if (!ParseArgs(argc - 1, argv + 1, &args)) {
        goto Usage;
    }

    if (!args.numLinks) {
        args.mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
    }
    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    if (args.encrypt == 1) {
        size_t i;
        for (i = 0; i < NUM_KEYS; ++i) {
            DPS_SetContentKey(memoryKeyStore, &PskId[i], &Psk[i]);
        }
    } else if (args.encrypt == 2) {
        DPS_SetTrustedCA(memoryKeyStore, TrustedCAs);
        nodeKeyId = &SubscriberId;
        DPS_SetCertificate(memoryKeyStore, SubscriberCert, SubscriberPrivateKey, SubscriberPassword);
        DPS_SetCertificate(memoryKeyStore, PublisherCert, NULL, NULL);
    } else if (args.encrypt == 3) {
        DPS_SetTrustedCA(memoryKeyStore, TrustedCAs);
        nodeKeyId = &SubscriberId;
        DPS_SetCertificate(memoryKeyStore, SubscriberCert, SubscriberPrivateKey, SubscriberPassword);
        DPS_SetCertificate(memoryKeyStore, PublisherCert, NULL, NULL);
    }
    subscriber.node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), nodeKeyId);
    DPS_SetNodeSubscriptionUpdateDelay(subscriber.node, args.subsRate);

    nodeDestroyed = DPS_CreateEvent();

    ret = DPS_StartNode(subscriber.node, args.mcastPub, args.listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(subscriber.node));

    if (args.wait) {
        /*
         * Wait for a while before trying to link
         */
        DPS_TimedWaitForEvent(nodeDestroyed, args.wait * 1000);
    }

    if (!Subscribe(&subscriber, &args)) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
    }
    if (!LinkTo(&subscriber, &args)) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
    }
    if (IsInteractive(&args)) {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(&subscriber);
        UnlinkFrom(&subscriber);
        DPS_DestroyNode(subscriber.node, OnNodeDestroyed, nodeDestroyed);
    }

Exit:
    if (ret != DPS_OK) {
        DPS_DestroyNode(subscriber.node, OnNodeDestroyed, nodeDestroyed);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    return (ret == DPS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;

Usage:
    DPS_PRINT("Usage %s [-d] [-q] [-m] [-w <seconds>] [-x 0|1|2|3] [[-h <hostname>] -p <portnum>] [-l <listen port] [-j] [-r <milliseconds>] [[-s] topic1 ... topicN]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -q: Quiet - suppresses output about received publications.\n");
    DPS_PRINT("       -x: Disable (0) or enable symmetric encryption (1), asymmetric encryption (2), or authentication (3). Default is symmetric encryption enabled.\n");
    DPS_PRINT("       -h: Specifies host (localhost is default). Mutiple -h options are permitted.\n");
    DPS_PRINT("       -w: Time to wait before establishing links\n");
    DPS_PRINT("       -p: A port to link. Multiple -p options are permitted.\n");
    DPS_PRINT("       -m: Enable multicast receive. Enabled by default is there are no -p options.\n");
    DPS_PRINT("       -l: port to listen on. Default is an ephemeral port.\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n");
    DPS_PRINT("       -s: list of subscription topic strings. Multiple -s options are permitted\n");
    DPS_PRINT("       -j: Treat payload as CBOR and attempt to decode an display as JSON\n");
    return EXIT_FAILURE;
}
