/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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
#include "test.h"
#include <dps/private/network.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>
#include "../src/node.h"

/*
 * This is just test code so to make it easy port numbers maps 1:1 into this array
 */
static uint16_t PortMap[UINT16_MAX];

/*
 * Maps node id's to DPS nodes
 */
static DPS_Node* NodeMap[UINT16_MAX];

/*
 * List of node id's from the input file
 */
static uint16_t NodeList[UINT16_MAX];

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    static const char AckFmt[] = "This is an ACK from %d";
    DPS_Status ret;
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t i;
    size_t numTopics;

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

    if (DPS_PublicationIsAckRequested(pub)) {
        char ackMsg[sizeof(AckFmt) + 8];

        sprintf(ackMsg, AckFmt, DPS_GetPortNumber(DPS_PublicationGetNode(pub)));

        ret = DPS_AckPublication(pub, (uint8_t*)ackMsg, sizeof(ackMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

typedef struct _LINK {
    uint16_t src;
    uint16_t dst;
    struct _LINK* next;
} LINK;

static LINK* links = NULL;

static LINK* HasLink(uint16_t src, uint16_t dst)
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        if (l->src == src && l->dst == dst) {
            return l;
        }
        if (l->dst == src && l->src == dst) {
            return l;
        }
    }
    return NULL;
}

static int IsNew(uint16_t n)
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        if (l->src == n || l->dst == n) {
            return 0;
        }
    }
    return 1;
}

static size_t NumArcs()
{
    size_t numArcs = 0;
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        ++numArcs;
    }
    return numArcs;
}

static LINK* AddLink(uint16_t src, uint16_t dst)
{
    LINK* l = HasLink(src, dst);
    if (!l) {
        l = calloc(1, sizeof(LINK));
        l->next = links;
        l->src = src;
        l->dst = dst;
        links = l;
    }
    return l;
}

static int StrArg(char* opt, char*** argp, int* argcp, const char** val)
{
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = *arg++;
    if (**val == '-') {
        DPS_PRINT("Value for option %s must be a string\n", opt);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
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

static uint16_t GetPort(DPS_NodeAddress* nodeAddr)
{
    const struct sockaddr* addr = (const struct sockaddr*)&nodeAddr->inaddr;
    if (addr->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
    } else {
        return ntohs(((const struct sockaddr_in*)addr)->sin_port);
    }
}

static int CountMutedLinks()
{
    int numMuted = 0;
    size_t i;

    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        DPS_Node* node = NodeMap[i];
        if (node) {
            RemoteNode* remote;
            for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
                if (remote->outbound.muted && remote->linked) {
                    ++numMuted;
                }
            }
        }
    }
    return numMuted;
}

static void DumpLinks()
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        DPS_PRINT("   %d -> %d;\n", l->src, l->dst);
    }
}

static int ReadLinks(const char* fn)
{
    int numIds = 0;
    FILE* f;

    f = fopen(fn, "r");
    if (!f) {
        DPS_PRINT("Could not open file %s\n", fn);
        return 0;
    }
    while (1) {
        int ep1;
        int ep2;
        size_t n = 0;
        ssize_t len;
        char line[32];

        if (fgets(line, sizeof(line), f) == NULL) {
            break;
        }
        len = strnlen(line, sizeof(line));
        if (len != 0) {
            char* l = line;
            char* e;

            ep1 = strtol(l, &e, 10);
            if (l != e) {
                l = e;
                ep2 = strtol(l, &e, 10);
            }
            if (l == e) {
                DPS_PRINT("Link requires two nodes\n");
                goto ErrExit;
            }
            if (ep1 == ep2) {
                DPS_PRINT("Cannot link to self\n");
                goto ErrExit;

            }
            if (IsNew(ep1)) {
                NodeList[numIds++] = ep1;
            }
            if (IsNew(ep2)) {
                NodeList[numIds++] = ep2;
            }
            AddLink(ep1, ep2);
        }
    }
    fclose(f);
    return numIds;

ErrExit:

    fclose(f);
    return 0;
}

static void DumpMeshIds(uint16_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        if (node) {
            DPS_PRINT("Node[%d] meshId %s\n", id, DPS_UUIDToString(&node->minMeshId));
        }
    }
}

static void DumpPortMap(uint16_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        DPS_PRINT("Node[%d] = %d\n", id, DPS_GetPortNumber(node));
    }
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_PRINT("Node %d destroyed\n", *(uint16_t*)data);
    }
}

const LinkMonitorConfig SlowLinkProbe = {
    .retries = 0,        /* Maximum number of retries following a probe failure */
    .probeTO = 1000000,  /* Repeat rate for probes */
    .retryTO = 10        /* Repeat time for retries following a probe failure */
};

static volatile int LinksUp;
static volatile int LinksFailed;

static uv_mutex_t lock;

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    uv_mutex_lock(&lock);
    if (status == DPS_OK) {
        ++LinksUp;
    } else {
        DPS_ERRPRINT("Failed to Link to %d - %s\n", DPS_GetPortNumber((DPS_Node*)data), DPS_ErrTxt(status));
        ++LinksFailed;
    }
    uv_mutex_unlock(&lock);
}

static void OnResolve(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    if (addr) {
        DPS_Status ret = DPS_Link(node, addr, OnLinked, data);
        if (ret != DPS_OK) {
            uv_mutex_lock(&lock);
            DPS_ERRPRINT("DPS_Link for %d returned %s\n", DPS_GetPortNumber((DPS_Node*)data), DPS_ErrTxt(ret));
            ++LinksFailed;
            uv_mutex_unlock(&lock);
        }
    } else {
        uv_mutex_lock(&lock);
        DPS_ERRPRINT("Failed to resolve address for %d\n", DPS_GetPortNumber((DPS_Node*)data));
        ++LinksFailed;
        uv_mutex_unlock(&lock);
    }
}

static DPS_Status LinkNodes(DPS_Node* src, DPS_Node* dst)
{
    DPS_Status ret;
    char port[8];
    snprintf(port, sizeof(port), "%d", DPS_GetPortNumber(dst));

    ret = DPS_ResolveAddress(src, NULL, port, OnResolve, dst);
    if (ret != DPS_OK) {
        uv_mutex_lock(&lock);
        ++LinksFailed;
        uv_mutex_unlock(&lock);
    }
    return ret;
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = argv + 1;
    LINK* l;
    DPS_Event* sleeper;
    int t;
    int maxSubs = 1;
    int numIds = 0;
    int numMuted = 0;
    int expMuted;
    const char* inFn = NULL;
    size_t i;

    DPS_Debug = 0;

    while (--argc) {
        if (StrArg("-f", &arg, &argc, &inFn)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (IntArg("-s", &arg, &argc, &maxSubs, 0, 32)) {
            continue;
        }
        if (*arg[0] == '-') {
            DPS_PRINT("Unknown option %s\n", arg[0]);
            return EXIT_FAILURE;
        }
        inFn = *arg++;
    }
    if (inFn) {
        numIds = ReadLinks(inFn);
        if (numIds == 0) {
            return EXIT_FAILURE;
        }
        DumpLinks();
    } else {
        DPS_PRINT("No input file\n");
        return EXIT_FAILURE;
    }

    /*
     * We are just using this as a platform independent wait
     */
    sleeper = DPS_CreateEvent();

    /*
     * Mutex for protecting the link success/fail counters
     */
    uv_mutex_init(&lock);

    for (t = 0; t < 1000; ++t) {
        int numLinks = 0;
        DPS_PRINT("Iteration %d\n", t);
        DPS_NodeAddress* addr = DPS_CreateAddress();
        /*
         * Start the nodes
         */
        for (i = 0; i < numIds; ++i) {
            DPS_Node* node = DPS_CreateNode("/.", NULL, NULL);
            /*
             * For test purposes we only want a short subscription delay
             */
            DPS_SetNodeSubscriptionUpdateDelay(node, 300);

            ret = DPS_StartNode(node, DPS_FALSE, 0);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
                return EXIT_FAILURE;
            }
            PortMap[DPS_GetPortNumber(node)] = NodeList[i];
            NodeMap[NodeList[i]] = node;
            /*
             * Set slow link monitor probes because we are
             * not detecting disconnects in this test program.
             */
            node->linkMonitorConfig = SlowLinkProbe;
        }
        /*
         * Wait for a short time while before trying to link
         */
        DPS_TimedWaitForEvent(sleeper, 500);
        /*
         * Link the nodes asynchronously
         */
        LinksUp = 0;
        LinksFailed = 0;
        for (l = links; l != NULL; l = l->next) {
            ret = LinkNodes(NodeMap[l->src], NodeMap[l->dst]);
            ++numLinks;
        }
        DPS_PRINT("%d nodes making %d links \n", numIds, numLinks);
        /*
         * Wait until all the links are up
         */
        uv_mutex_lock(&lock);
        while ((LinksUp + LinksFailed) < numLinks) {
            uv_mutex_unlock(&lock);
            DPS_TimedWaitForEvent(sleeper, 100);
            uv_mutex_lock(&lock);
        }
        uv_mutex_unlock(&lock);
        DPS_PRINT("%d links up %d links failed\n", LinksUp, LinksFailed);
        /*
         * Brief delay to let things settle down
         */
        DPS_TimedWaitForEvent(sleeper, 1000);
#ifndef NDEBUG
        {
            extern int _DPS_NumSubs;
            DPS_PRINT("Sent %d subs\n", _DPS_NumSubs);
            _DPS_NumSubs = 0;
        }
#endif
        /*
         * Add subscriptions to a random node
         */
        for (i = 0; i < maxSubs; ++i) {
            DPS_Node* node = NodeMap[NodeList[DPS_Rand() %numIds]];
            DPS_Subscription* sub;
            char topic[2];
            const char* topicList[] = { topic };
            topic[0] = (char)('A' + i);
            topic[1] = 0;
            sub = DPS_CreateSubscription(node, topicList, 1);
            if (!sub) {
                DPS_ERRPRINT("CreateSubscribe failed\n");
            }
            ret = DPS_Subscribe(sub, OnPubMatch);
            if (ret == DPS_OK) {
                break;
            }
            DPS_ERRPRINT("Subscribe failed %s\n", DPS_ErrTxt(ret));
            return EXIT_FAILURE;
        }
        /*
         * Check we got the result we expected
         */
        expMuted = numLinks + 1 - numIds;
        for (i = 0; i < 100; ++i) {
            numMuted = CountMutedLinks();
            if (numMuted >= expMuted) {
                break;
            }
            DPS_TimedWaitForEvent(sleeper, 100);
        }
        /*
         * Wait in case we missed some muted nodes
         */
        DPS_TimedWaitForEvent(sleeper, 1000);
        numMuted = CountMutedLinks();

        if (numMuted != expMuted) {
            DPS_ERRPRINT("Wrong number of muted nodes: Expected %d got %d\n", expMuted, numMuted);
            ASSERT(expMuted == numMuted);
        }
#ifndef NDEBUG
        {
            extern int _DPS_NumSubs;
            DPS_PRINT("Sent %d subs\n", _DPS_NumSubs);
            _DPS_NumSubs = 0;
        }
#endif
        /*
         * Cleanup the nodes
         */
        for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
            if (NodeMap[i]) {
                DPS_DestroyNode(NodeMap[i], OnNodeDestroyed, NULL);
                NodeMap[i] = NULL;
            }
        }
        DPS_DestroyAddress(addr);

    }
    DPS_DestroyEvent(sleeper);

    return EXIT_SUCCESS;
}
