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

#define MAX_TOPICS 64
#define MAX_TOPIC_LEN 128
#define MAX_MSG_LEN 128

static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static int requestAck = DPS_FALSE;

static DPS_Publication* currentPub = NULL;

static DPS_Event* nodeDestroyed;

static uint8_t keyId[] = { 0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2 };

/*
 * Preshared key for testing only
 */
static uint8_t keyData[] = { 0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10 };

DPS_Status GetKey(DPS_Node* node, DPS_UUID* kid, uint8_t* key, size_t keyLen)
{
    if (memcmp(kid, keyId, sizeof(DPS_UUID)) == 0) {
        memcpy(key, keyData, keyLen);
        return DPS_OK;
    } else {
        return DPS_ERR_MISSING;
    }
}

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
    uint8_t* data;
    char lineBuf[200];

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
            ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, requestAck ? OnAck : NULL);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
                return;
            }
        }
        ret = DPS_Publish(currentPub, msg, msg ? strnlen(msg, MAX_MSG_LEN) : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)), DPS_PublicationGetSequenceNum(currentPub));
        } else {
            DPS_ERRPRINT("Failed to publish %s error=%s\n", lineBuf, DPS_ErrTxt(ret));
        }
    }
}


static DPS_Status FindAndLink(DPS_Node* node, const char* host, uint16_t port, const char* tenant, DPS_NodeAddress* remoteAddr)
{
    DPS_Status ret;
    DPS_RegistrationList* regs = DPS_CreateRegistrationList(16);

    /*
     * Find nodes to link to
     */
    ret = DPS_Registration_GetSyn(node, host, port, tenant, regs);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Registration service lookup failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }
    DPS_PRINT("Found %d remote nodes\n", regs->count);

    if (regs->count == 0) {
        return DPS_ERR_NO_ROUTE;
    }
    ret = DPS_Registration_LinkToSyn(node, regs, remoteAddr);
    if (ret == DPS_OK) {
        DPS_PRINT("Linked to remote node %s\n", DPS_NodeAddrToString(remoteAddr));
    }
    DPS_DestroyRegistrationList(regs);
    return ret;
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

int main(int argc, char** argv)
{
    DPS_Status ret;
    char* topics[64];
    char** arg = ++argv;
    const char* tenant = "anonymous_tenant";
    size_t numTopics = 0;
    DPS_Node* node;
    DPS_NodeAddress* remoteAddr;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = "localhost";
    char* msg = NULL;
    int ttl = 0;
    int port = 30000;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-p", &arg, &argc, &port, 1, UINT16_MAX)) {
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
        if (strcmp(*arg, "--msg") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            msg = *arg++;
            continue;
        }
        if (IntArg("--ttl", &arg, &argc, &ttl, 0, 2000)) {
            continue;
        }
        if (strcmp(*arg, "--request-ack") == 0) {
            ++arg;
            requestAck = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-t") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            tenant = *arg++;
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
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }

    if (!host || !port) {
        DPS_PRINT("Need host name and port\n");
        goto Usage;
    }

    node = DPS_CreateNode("/.", GetKey, (DPS_UUID*)keyId);

    ret = DPS_StartNode(node, mcastPub, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    remoteAddr = DPS_CreateAddress();

    nodeDestroyed = DPS_CreateEvent();

    ret = FindAndLink(node, host, port, tenant, remoteAddr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to link to node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }

    if (numTopics) {
        currentPub = DPS_CreatePublication(node);
        ret = DPS_InitPublication(currentPub, (const char**)topics, numTopics, DPS_FALSE, requestAck ? OnAck : NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
            goto Exit;
        }
        ret = DPS_Publish(currentPub, msg, msg ? strnlen(msg, MAX_MSG_LEN) + 1 : 0, ttl);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(currentPub)));
        } else {
            DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        }
        DPS_UnlinkFrom(node, remoteAddr);
        DPS_DestroyAddress(remoteAddr);
    } else {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(node);
    }

Exit:
    DPS_DestroyNode(node, OnNodeDestroyed, NULL);
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-h <hostname>] [-p <portnum>] [-t <tenant string>] [--ttl <pub ttl>] [--msg <message>] topic1 topic2 ... topicN\n", *argv);
    return 1;
}
