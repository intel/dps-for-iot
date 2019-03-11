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
#include "common.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define MAX_TOPICS 64
#define MAX_MSG_LEN 128

static int pubCount = 1;
static int ttl = 0;
static int quiet = DPS_FALSE;

static DPS_Event* nodeDestroyed;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent(nodeDestroyed, DPS_OK);
}

static void OnAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Node* node = DPS_PublicationGetNode(pub);

    if (!quiet) {
        DPS_PRINT("Ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), DPS_PublicationGetSequenceNum(pub));
        if (len) {
            DPS_PRINT("    %.*s\n", (int)len, data);
        }
    }
    if (--pubCount) {
        DPS_Status ret = DPS_Publish(pub, NULL, 0, ttl);
        if (ret == DPS_OK) {
            return;
        }
        DPS_ERRPRINT("Failed to publish: %s\n", DPS_ErrTxt(ret));
    }
    DPS_DestroyPublication(pub);
    DPS_DestroyNode(node, OnNodeDestroyed, NULL);
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    const char* topics[MAX_TOPICS];
    size_t numTopics = 0;
    DPS_Publication* pub = NULL;
    DPS_Node* node;
    char** arg = argv + 1;
    DPS_NodeAddress* linkAddr[MAX_LINKS] = { NULL };
    char* linkText[MAX_LINKS] = { NULL };
    int numLinks = 0;
    char* msg = NULL;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;

    DPS_Debug = 0;

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
        if (IntArg("-t", &arg, &argc, &ttl, 0, 2000)) {
            continue;
        }
        if (IntArg("-c", &arg, &argc, &pubCount, 1, INT32_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (strcmp(*arg, "-q") == 0) {
            ++arg;
            quiet = DPS_TRUE;
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
    }

    node = DPS_CreateNode("/.", NULL, NULL);
    ret = DPS_StartNode(node, mcast, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    ret = Link(node, linkText, linkAddr, numLinks);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_ResolveAddress returned %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    pub = DPS_CreatePublication(node);
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, NULL, OnAck);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
        return 1;
    }

    nodeDestroyed = DPS_CreateEvent();

    ret = DPS_Publish(pub, (uint8_t*)msg, msg ? strnlen(msg, MAX_MSG_LEN) + 1 : 0, ttl);
    if (ret == DPS_OK) {
        DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)));
    } else {
        DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        DPS_DestroyPublication(pub);
        DPS_DestroyNode(node, OnNodeDestroyed, NULL);
    }

    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DestroyLinkArg(linkText, linkAddr, numLinks);

    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-p <address>] [-m <message>] [-t <ttl>] [-c <count>] [topic1 topic2 ... topicN]\n", *argv);
    return 1;
}


