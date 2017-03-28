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
#include <assert.h>
#include <uv.h>
#include <dps/private/network.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>
#include "../src/node.h"

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    static uint8_t AckFmt[] = "This is an ACK from %d";
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

        ret = DPS_AckPublication(pub, ackMsg, sizeof(ackMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

typedef struct _LINK {
    uint16_t src;
    uint16_t dst;
    int muted;
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

static void AddLink(uint16_t src, uint16_t dst)
{
    if (!HasLink(src, dst)) {
        LINK* newLink = calloc(1, sizeof(LINK));
        newLink->next = links;
        newLink->src = src;
        newLink->dst = dst;
        links = newLink;
    }
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

#define BASE_PORT 60000
#define PORT_NUM(n)  ((uint16_t)((n) + BASE_PORT))


static uint16_t GetPort(DPS_NodeAddress* nodeAddr)
{
    const struct sockaddr* addr = (const struct sockaddr*)&nodeAddr->inaddr;
    if (addr->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
    } else {
        return ntohs(((const struct sockaddr_in*)addr)->sin_port);
    }
}

static size_t MuteLinks(DPS_Node* node)
{
    size_t numMuted = 0;
    RemoteNode* remote;

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        if (remote->muted) {
            uint16_t port = GetPort(&remote->ep.addr);
            LINK* link = HasLink(node->port, port);
            if (!link) {
                DPS_ERRPRINT("Missing link %d -> %d\n", node->port, port);
            } else {
                if (!link->muted) {
                    ++numMuted;
                }
                ++link->muted;
                assert(link->muted <= 2);
            }
        }
    }
    return numMuted;
}

static void PrintGraph(DPS_Node** node, size_t numNodes, const char* outFn, int showMuted)
{
    FILE* f = NULL;
    size_t numMuted = 0;
    static const char* style[] = {
        "",
        " [color=gray20, style=dotted]",
        " [color=red, style=dotted]",
    };
    LINK* l;
    size_t i;

    for (i = 0; i < numNodes; ++i) {
        numMuted += MuteLinks(node[i]);
    }

    if (outFn) {
        f = fopen(outFn, "w");
        if (!f) {
            DPS_PRINT("Could not open %s for writing\n");
            f = stdout;
        }
    }
    if (!f) {
        f = stdout;
    }

    fprintf(f, "graph {\n");
    fprintf(f, "  node[shape=circle, width=0.3, fontsize=10, margin=\"0.01,0.01\", fixedsize=true];\n");
    if (showMuted) {
        fprintf(f, "  epsilon=0.00005;\n");
        fprintf(f, "  overlap=scale;\n");
    } else {
        fprintf(f, "  overlap=false;\n");
    }
    fprintf(f, "  splines=true;\n");
    for (l = links; l != NULL; l = l->next) {
        if (showMuted || (l->muted == 0)) {
            fprintf(f, "  %d -- %d%s;\n", l->src - BASE_PORT, l->dst - BASE_PORT, style[l->muted]);
        }
    }
    fprintf(f, "  labelloc=t;\n");
    fprintf(f, "  label=\"Nodes=%d arcs=%d muted=%d\";\n", (int)numNodes, (int)NumArcs(), (int)numMuted);
    fprintf(f, "}\n");

    if (f != stdout) {
        fclose(f);
    }
}

static void DumpLinks()
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        DPS_PRINT("   %d -> %d;\n", l->src, l->dst);
    }
}

#define MAX_NODES 1024

static int ReadLinks(const char* fn, uint16_t* nodes)
{
    int numNodes = 0;
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
            ep1 = PORT_NUM(ep1);
            ep2 = PORT_NUM(ep2);
            if (IsNew(ep1)) {
                nodes[numNodes++] = ep1;
            }
            if (IsNew(ep2)) {
                nodes[numNodes++] = ep2;
            }
            AddLink(ep1, ep2);
        }
    }
    fclose(f);
    return numNodes;

ErrExit:

    fclose(f);
    return 0;
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = argv + 1;
    LINK* l;
    DPS_Node* node[MAX_NODES];
    uint16_t nodePort[MAX_NODES];
    DPS_Event* sleeper;
    int numNodes = 2;
    int numLinks = 0;
    int showMuted = 1;
    int maxSubs = 1;
    int numSubs = 0;
    const char* inFn = NULL;
    const char* outFn = NULL;
    size_t i;

    DPS_Debug = 0;

    while (--argc) {
        if (StrArg("-f", &arg, &argc, &inFn)) {
            continue;
        }
        if (StrArg("-o", &arg, &argc, &outFn)) {
            continue;
        }
        if (IntArg("-s", &arg, &argc, &maxSubs, 0, 10000)) {
            continue;
        }
        if (IntArg("-m", &arg, &argc, &showMuted, 0, 1)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (IntArg("-n", &arg, &argc, &numNodes, 2, UINT16_MAX)) {
            continue;
        }
    }
    if (inFn) {
        numNodes = ReadLinks(inFn, nodePort);
        if (numNodes == 0) {
            return 1;
        }
        DumpLinks();
    } else {
        for (i = 0; i < numNodes; ++i) {
            nodePort[i] = PORT_NUM(i);
        }
    }

    /*
     * Start the nodes
     */
    for (i = 0; i < numNodes; ++i) {
        node[i] = DPS_CreateNode("/.", NULL, NULL);
        ret = DPS_StartNode(node[i], DPS_FALSE, nodePort[i]);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }
    sleeper = DPS_CreateEvent();
    /*
     * Wait for a short time while before trying to link
     */
    DPS_TimedWaitForEvent(sleeper, 2000);
    /*
     * Link the nodes
     */
    for (l = links; l != NULL; l = l->next) {
        DPS_NodeAddress* addr = DPS_CreateAddress();
        for (i = 0; i < numNodes; ++i) {
            if (DPS_GetPortNumber(node[i]) == l->src) {
                break;
            }
        }
        assert(i < numNodes);
        ret = DPS_LinkTo(node[i], NULL, l->dst, addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Node %d connected to node %d\n", l->src, l->dst);
            ++numLinks;
        } else {
            DPS_ERRPRINT("Failed to link %d to %d returned %s\n", l->src, l->dst, DPS_ErrTxt(ret));
        }
        DPS_DestroyAddress(addr);
    }

    DPS_PRINT("%d nodes created %d links \n", numNodes, numLinks);

    DPS_TimedWaitForEvent(sleeper, 100);
    /*
     * Add some subscriptions
     */
    while (maxSubs > 0) {
        for (i = 0; i < numNodes && numSubs < maxSubs; ++i) {
            if ((DPS_Rand() % 4) == 0) {
                DPS_Subscription* sub;
                char topic[] = "A";
                const char* topicList[] = { topic };

                topic[0] += DPS_Rand() % 26;
                sub = DPS_CreateSubscription(node[i], topicList, 1);
                if (!sub) {
                    DPS_ERRPRINT("CreateSubscribe failed\n");
                    break;
                }
                ret = DPS_Subscribe(sub, OnPubMatch);
                if (ret == DPS_OK) {
                    ++numSubs;
                } else {
                    DPS_ERRPRINT("Subscribe failed %s\n", DPS_ErrTxt(ret));
                }
                DPS_TimedWaitForEvent(sleeper, DPS_Rand() % 100);
            }
        }
        /*
         * Need to have at least one subscription
         */
        if (numSubs > 0) {
            maxSubs = 0;
        }
    }

    DPS_TimedWaitForEvent(sleeper, 1000);

    PrintGraph(node, numNodes, outFn, showMuted);

    DPS_DestroyEvent(sleeper);

    for (i = 0; i < numNodes; ++i) {
        DPS_DestroyNode(node[i], NULL, OnNodeDestroyed);
    }

    return 0;
}
