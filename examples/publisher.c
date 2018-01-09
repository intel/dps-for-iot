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
#include "keys.h"

#define MAX_TOPICS 64
#define MAX_MSG_LEN 128
#define MAX_TOPIC_LEN 256

static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static int requestAck = DPS_FALSE;

static DPS_Publication* currentPub = NULL;

static DPS_Event* nodeDestroyed;

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
                if (!sscanf(topicList, "-x %d", encrypt) || (*encrypt < 0) || (*encrypt > 2)) {
                    DPS_PRINT("-x requires 0..2\n");
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
                DPS_PRINT("  [topic1 ... topicN  [-x 0|1|2]] [-t <ttl>] [-m message]\n");
                DPS_PRINT("        -h: Print this message\n");
                DPS_PRINT("        -t: Set ttl on the publication\n");
                DPS_PRINT("        -x: Disable (0) or enable symmetric (1) or asymmetric(2) encryption. Default is symmetric encryption enabled.\n");
                DPS_PRINT("        -m: Everything after the -m is the payload for the publication.\n");
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
            ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE,
                                      NULL, 0, requestAck ? OnAck : NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to create publication - error=%s\n", DPS_ErrTxt(ret));
                break;
            }
            if (encrypt) {
                ret = DPS_PublicationAddKeyId(currentPub, (const uint8_t*)&PskId[0], sizeof(DPS_UUID));
                if (ret != DPS_OK) {
                    DPS_ERRPRINT("Failed to add key ID - error=%s\n", DPS_ErrTxt(ret));
                    break;
                }
            }
        }
        ret = DPS_Publish(currentPub, msg, msg ? strnlen(msg, MAX_MSG_LEN) : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)),
                      DPS_PublicationGetSequenceNum(currentPub));
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
    const char* nodeKeyId = NULL;
    DPS_Node* node;
    char** arg = argv + 1;
    const char* host = NULL;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int numLinks = 0;
    int wait = 0;
    int encrypt = 1;
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
        if (IntArg("-x", &arg, &argc, &encrypt, 0, 2)) {
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

    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, (const uint8_t*)&NetworkKeyId, sizeof(DPS_UUID), NetworkKey, sizeof(NetworkKey));
    if (encrypt == 1) {
        for (size_t i = 0; i < NUM_KEYS; ++i) {
            DPS_SetContentKey(memoryKeyStore, &PskId[i], PskData[i], 16);
        }
    } else if (encrypt == 2) {
        DPS_SetTrustedCA(memoryKeyStore, TrustedCAs, strlen(TrustedCAs) + 1);
        nodeKeyId = PublisherId;
        DPS_SetCertificate(memoryKeyStore, PublisherCert, strlen(PublisherCert) + 1,
                           PublisherPrivateKey, strlen(PublisherPrivateKey) + 1,
                           PublisherPassword, strlen(PublisherPassword));
        DPS_SetCertificate(memoryKeyStore, SubscriberCert, strlen(SubscriberCert) + 1, NULL, 0, NULL, 0);
    }

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), nodeKeyId, nodeKeyId ? strlen(nodeKeyId) : 0);
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

        ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE,
                                  NULL, 0, requestAck ? OnAck : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%s\n", DPS_ErrTxt(ret));
            return 1;
        }
        if (encrypt == 2)  {
            ret = DPS_PublicationAddKeyId(currentPub, SubscriberId, strlen(SubscriberId));
        } else if (encrypt == 1) {
            ret = DPS_PublicationAddKeyId(currentPub, (const uint8_t*)&PskId[1], sizeof(DPS_UUID));
        }
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to add key ID - error=%s\n", DPS_ErrTxt(ret));
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
    DPS_PRINT("Usage %s [-d] [-x 0|1|2] [-a] [-w <seconds>] <seconds>] [-t <ttl>] [[-h <hostname>] -p <portnum>] [-l <portnum>] [-m <message>] [-r <milliseconds>] [topic1 topic2 ... topicN]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -x: Disable (0) or enable symmetric (1) or asymmetric(2) encryption. Default is symmetric encryption enabled.\n");
    DPS_PRINT("       -a: Request an acknowledgement\n");
    DPS_PRINT("       -t: Set a time-to-live on a publication\n");
    DPS_PRINT("       -w: Time to wait between linking to remote node and sending publication\n");
    DPS_PRINT("       -l: Port number to listen on for incoming connections\n");
    DPS_PRINT("       -h: Specifies host (localhost is default). Mutiple -h options are permitted.\n");
    DPS_PRINT("       -p: port to link. Multiple -p options are permitted.\n");
    DPS_PRINT("       -m: A payload message to accompany the publication.\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n");
    DPS_PRINT("           Enters interactive mode if there are no topic strings on the command line.\n");
    DPS_PRINT("           In interactive mode type -h for commands.\n");
    return 1;
}


