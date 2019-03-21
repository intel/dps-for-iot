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
#include <dps/registration.h>
#include <dps/event.h>
#include "common.h"
#include "keys.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define MAX_TOPICS 64
#define MAX_TOPIC_LEN 128
#define MAX_MSG_LEN 128

static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static int requestAck = DPS_FALSE;

static DPS_Publication* currentPub = NULL;

static DPS_Event* nodeDestroyed;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent(nodeDestroyed, DPS_OK);
}

static int AddTopics(char* topicList, char** msg, int* keep, int* ttl)
{
    size_t i;

    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
    }
    *msg = NULL;
    *keep = 0;
    *ttl = 0;
    numTopics = 0;
    while (numTopics < MAX_TOPICS) {
        size_t len = strcspn(topicList, " ");
        if (!len) {
            len = strnlen(topicList, MAX_TOPIC_LEN);
        }
        if (topicList[0] == '-') {
            switch(topicList[1]) {
            case 't':
                if (!sscanf(topicList, "-t %d", ttl)) {
                    return 0;
                }
                topicList += 3;
                break;
            case 'm':
                /*
                 * After "-m" the rest of the line is a message
                 */
                *msg = topicList + 1 + len;
                return 1;
            case 'k':
                *keep = 1;
                break;

            }
            len = strcspn(topicList, " ");
            if (!len) {
                return 0;
            }
        } else {
            topics[numTopics] = malloc(len + 1);
            memcpy(topics[numTopics], topicList, len);
            topics[numTopics][len] = 0;
            ++numTopics;
            if (!topicList[len]) {
                break;
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
        char* msg;
        DPS_Status ret;

        while (len && isspace(lineBuf[len - 1])) {
            --len;
        }
        if (!len) {
            continue;
        }
        lineBuf[len] = 0;

        DPS_PRINT("Pub: %s\n", lineBuf);

        if (!AddTopics(lineBuf, &msg, &keep, &ttl)) {
            DPS_PRINT("Invalid\n");
            return;
        }
        if (!currentPub) {
            keep = 0;
        }
        if (!keep) {
            DPS_DestroyPublication(currentPub);
            currentPub = DPS_CreatePublication(node);
            ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, NULL,
                                      requestAck ? OnAck : NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
                return;
            }
        }
        ret = DPS_Publish(currentPub, (uint8_t*)msg, msg ? strnlen(msg, MAX_MSG_LEN) : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)), DPS_PublicationGetSequenceNum(currentPub));
        } else {
            DPS_ERRPRINT("Failed to publish %s error=%s\n", lineBuf, DPS_ErrTxt(ret));
        }
    }
}

static DPS_Status FindAndLink(DPS_Node* node, char** linkText, int numLinks, const char* tenant,
                              uint8_t count, uint16_t timeout, DPS_NodeAddress** linkAddr)
{
    DPS_Status ret = DPS_OK;
    DPS_RegistrationList* regs = NULL;
    int i;

    for (i = 0; i < numLinks; ++i) {
        /*
         * Find nodes to link to
         */
        regs = DPS_CreateRegistrationList(count);
        ret = DPS_Registration_GetSyn(node, linkText[i], tenant, regs, timeout);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Registration service lookup failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
        DPS_PRINT("Found %d remote nodes\n", regs->count);
        if (regs->count == 0) {
            return DPS_ERR_NO_ROUTE;
        }
        linkAddr[i] = DPS_CreateAddress();
        if (!linkAddr[i]) {
            return DPS_ERR_RESOURCES;
        }
        ret = DPS_Registration_LinkToSyn(node, regs, linkAddr[i]);
        if (ret == DPS_OK) {
            char* str = NULL;
            /*
             * DPS_NodeAddrToString uses a static buffer, so dup one of
             * the strs used below.
             */
            str = strdup(DPS_GetListenAddressString(node));
            DPS_PRINT("%s is linked to %s\n", str, DPS_NodeAddrToString(linkAddr[i]));
            if (str) {
                free(str);
            }
        }
        DPS_DestroyRegistrationList(regs);
    }
    return ret;
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char* topics[64];
    char** arg = ++argv;
    const char* tenant = "anonymous_tenant";
    size_t numTopics = 0;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    DPS_Node* node;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    char* msg = NULL;
    int ttl = 0;
    int wait = 0;
    int subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
    int timeout = DPS_REGISTRATION_GET_TIMEOUT;
    int count = 16;
    DPS_NodeAddress* linkAddr[MAX_LINKS] = { NULL };
    char* linkText[MAX_LINKS] = { NULL };
    int numLinks = 0;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (LinkArg(&arg, &argc, linkText, &numLinks)) {
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
        if (IntArg("-w", &arg, &argc, &wait, 0, 30)) {
            continue;
        }
        if (IntArg("-r", &arg, &argc, &subsRate, 0, INT32_MAX)) {
            continue;
        }
        if (IntArg("-t", &arg, &argc, &ttl, 0, 2000)) {
            continue;
        }
        if (IntArg("-c", &arg, &argc, &count, 1, UINT8_MAX)) {
            continue;
        }
        if (IntArg("--timeout", &arg, &argc, &timeout, 0, UINT16_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            requestAck = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "--tenant") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            tenant = *arg++;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topics)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }

    if (!numLinks) {
        DPS_PRINT("Need link addresses\n");
        goto Usage;
    }

    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), NULL);
    DPS_SetNodeSubscriptionUpdateDelay(node, subsRate);

    ret = DPS_StartNode(node, mcastPub, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Publisher is listening on %s\n", DPS_GetListenAddressString(node));

    nodeDestroyed = DPS_CreateEvent();

    ret = FindAndLink(node, linkText, numLinks, tenant, count, timeout, linkAddr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to link to node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }

    if (numTopics) {
        currentPub = DPS_CreatePublication(node);
        ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, NULL,
                                  requestAck ? OnAck : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
            goto Exit;
        }
        if (wait) {
            /*
             * Wait for a while before sending a publication
             */
            DPS_TimedWaitForEvent(nodeDestroyed, wait * 1000);
        }
        ret = DPS_Publish(currentPub, (uint8_t*)msg, msg ? strnlen(msg, MAX_MSG_LEN) + 1 : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)));
        } else {
            DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        }
        /*
         * A brief delay before exiting to ensure the publication
         * gets sent and we have a chance to receive acks if requested
         */
        DPS_TimedWaitForEvent(nodeDestroyed, requestAck ? 2000 : 500);
        Unlink(node, linkAddr, numLinks);
    } else {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(node);
    }

Exit:
    DPS_DestroyNode(node, OnNodeDestroyed, NULL);
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    DestroyLinkArg(linkText, linkAddr, numLinks);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-a] [-w <seconds>] [-t <pub ttl>] [-p <address>] [--tenant <tenant string>] [-c <count>] [--timeout <milliseconds>] [-m <message>] [-r <milliseconds>] [topic1 topic2 ... topicN]\n", *argv);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -a: Request an acknowledgement\n");
    DPS_PRINT("       -t: Set a time-to-live on a publication\n");
    DPS_PRINT("       -w: Time to wait between linking to remote node and sending publication\n");
    DPS_PRINT("       -p: Address to link. Multiple -p options are permitted.\n");
    DPS_PRINT("       -m: A payload message to accompany the publication.\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n");
    DPS_PRINT("       --tenant: Tenant string to use.\n");
    DPS_PRINT("       -c: Size of registration get request.\n");
    DPS_PRINT("       --timeout: Timeout of registration get request.\n");
    DPS_PRINT("           Enters interactive mode if there are no topic strings on the command line.\n");
    DPS_PRINT("           In interactive mode type -h for commands.\n");
    return 1;
}
