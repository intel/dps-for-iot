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

#include "test.h"
#include "node.h"

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

static uint8_t SubsList[UINT16_MAX];

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    static const char AckFmt[] = "This is an ACK from %s";
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
        char ackMsg[sizeof(AckFmt) + 64];
        sprintf(ackMsg, AckFmt,
                DPS_GetListenAddressString(DPS_PublicationGetNode(pub)));
        ret = DPS_AckPublication(pub, (uint8_t*)ackMsg, sizeof(ackMsg));
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

static uint16_t GetPort(const DPS_NodeAddress* nodeAddr)
{
    const struct sockaddr* addr = (const struct sockaddr*)&nodeAddr->u.inaddr;
    if (addr->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
    } else {
        return ntohs(((const struct sockaddr_in*)addr)->sin_port);
    }
}

static uint16_t GetPortNumber(DPS_Node* node)
{
    return GetPort(DPS_GetListenAddress(node));
}

static int AddLinksForNode(DPS_Node* node)
{
    RemoteNode* remote;
    int numMuted = 0;
    uint16_t nodeId = PortMap[GetPortNumber(node)];

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        uint16_t port = GetPort(&remote->ep.addr);
        uint16_t id = PortMap[port];
        /*
         * Ignore dead nodes
         */
        if (NodeMap[id]) {
            LINK* link = AddLink(nodeId, id);
            if (remote->inbound.muted) {
                link->muted = 1;
                ++numMuted;
            }
        }
    }
    return numMuted;
}

static int MakeLinks(int* numNodes, int* numMuted)
{
    size_t i;
    int numArcs = 0;
    LINK* l;

    *numMuted = 0;
    *numNodes = 0;

    /* Delete stale link info */
    while (links) {
        l = links;
        links = links->next;
        free(l);
    }
    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        if (NodeMap[i]) {
            *numMuted += AddLinksForNode(NodeMap[i]);
            *numNodes += 1;
        }
    }
    for (l = links; l != NULL; l = l->next) {
        ++numArcs;
    }
    return numArcs;
}

static void PrintSubgraph(FILE* f, int showMuted, uint16_t* kills, size_t numKills, int expMuted, const char* color, int* label)
{
    static int cluster = 0;
    static int base = 0;
    static const char* style[] = {
        " [len=1]",
        " [color=red, style=dotted, len=2, weight=2]"
    };
    LINK* l;
    size_t i;
    int numNodes;
    int numArcs;
    int numMuted;
    int maxN = 0;

    numArcs = MakeLinks(&numNodes, &numMuted);
    if (numMuted & 1) {
        DPS_ERRPRINT("Odd number of muted links - something went wrong\n");
    }
    DPS_PRINT("Nodes=%d, muted=%d\n", (int)numNodes, (int)(numMuted / 2));

    if (*label == 0) {
        *label = base + 1000;
        fprintf(f, "  %d[shape=none, width=1, style=bold, height=1, fontsize=12, label=\"nodes=%d\\narcs=%d\\nmuted=%d", *label, (int)numNodes, (int)numArcs, (int)(numMuted / 2));
        if (expMuted != (numMuted / 2)) {
            fprintf(f, "/%d\"];\n", (int)expMuted);
        } else {
            fprintf(f, "\"];\n");
        }
    }

    fprintf(f, "subgraph cluster%d {\n", ++cluster);
    fprintf(f, "  node[style=filled, fillcolor=%s];\n", color);
    for (i = 0; i < numKills; ++i) {
        fprintf(f, "  %d[style=filled, fillcolor=azure2];\n", kills[i] + base);
    }
    for (l = links; l != NULL; l = l->next) {
        int src = l->src + base;
        int dst = l->dst + base;
        if (showMuted || (l->muted == 0)) {
            fprintf(f, "  %d -- %d%s;\n", src, dst, style[l->muted]);
            fprintf(f, "  %d[label=%d%s];\n", src, l->src, SubsList[l->src] ? ",shape=Mcircle" : "");
            fprintf(f, "  %d[label=%d%s];\n", dst, l->dst, SubsList[l->dst] ? ",shape=Mcircle" : "");
        }
        maxN  = (src > maxN) ? src : maxN;
        maxN  = (dst > maxN) ? dst : maxN;
    }
    fprintf(f, "}\n");
    fprintf(f, "  %d -- %d[style=invis];\n", maxN, *label);

    base += maxN + 1;
}

static int CountMuted(DPS_Node* node)
{
    int numMuted = 0;
    RemoteNode* remote;

    DPS_LockNode(node);
    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        uint16_t port = GetPort(&remote->ep.addr);
        uint16_t id = PortMap[port];
        /*
         * Ignore dead nodes
         */
        if (NodeMap[id] && remote->inbound.muted) {
            ++numMuted;
        }
    }
    DPS_UnlockNode(node);
    return numMuted;
}

static int CountMutedLinks(void)
{
    int numMuted = 0;
    size_t i;

    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        DPS_Node* node = NodeMap[i];
        if (node) {
            numMuted += CountMuted(node);
        }
    }
    return numMuted / 2;
}

static void DumpLinks(void)
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

static void DumpMeshIds(size_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        if (node) {
            DPS_PRINT("Node[%d] meshId %s\n", id, DPS_UUIDToString(&node->meshId));
            DPS_PRINT("Node[%d] minMeshId %s\n", id, DPS_UUIDToString(&node->minMeshId));
        }
    }
}

static void DumpPortMap(size_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        DPS_PRINT("Node[%d] = %d\n", id, GetPortNumber(node));
    }
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_PRINT("Node %d destroyed\n", *(uint16_t*)data);
    }
}

/*
 * This is a little tricky because during link recovery the number
 * of muted links can go down and then go up again so we check that
 * we get the same count mutiple times before we conclude that things
 * have settled.
 */
static void WaitUntilSettled(DPS_Event* sleeper, size_t expMuted)
{
    size_t i;
    size_t numMuted;
    int repeats = 0;

    DPS_PRINT("Expect %d links muted\n", expMuted);
    for (i = 0; i < 500; ++i) {
        DPS_TimedWaitForEvent(sleeper, 100);
        numMuted = CountMutedLinks();
        if (numMuted == expMuted) {
            if (++repeats == 5) {
                break;
            }
        } else {
            repeats = 0;
        }
    }
    if (numMuted != expMuted) {
        DPS_PRINT("ERROR: expected %d muted but got %d\n", expMuted, numMuted);
    }
}

static volatile int LinksUp;
static volatile int LinksFailed;

static uv_mutex_t lock;

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    uv_mutex_lock(&lock);
    if (status == DPS_OK) {
        ++LinksUp;
    } else {
        DPS_ERRPRINT("Failed to Link to %s - %s\n", DPS_NodeAddrToString(addr), DPS_ErrTxt(status));
        ++LinksFailed;
    }
    uv_mutex_unlock(&lock);
}

static DPS_Status LinkNodes(DPS_Node* src, DPS_Node* dst)
{
    DPS_Status ret;
    ret = DPS_Link(src, DPS_GetListenAddressString(dst), OnLinked, NULL);
    if (ret != DPS_OK) {
        uv_mutex_lock(&lock);
        DPS_ERRPRINT("DPS_Link for %s returned %s\n", DPS_GetListenAddressString(dst),
                     DPS_ErrTxt(ret));
        ++LinksFailed;
        uv_mutex_unlock(&lock);
    }
    return ret;
}

const LinkMonitorConfig FastLinkProbe = {
    .retries = 0,     /* Maximum number of retries following a probe failure */
    .probeTO = 500,   /* Repeat rate for probes */
    .retryTO = 10     /* Repeat time for retries following a probe failure */
};

#define MAX_KILLS  16

int main(int argc, char** argv)
{
    FILE* dotFile = NULL;
    DPS_Status ret;
    char** arg = argv + 1;
    LINK* l;
    DPS_Event* sleeper;
    int numIds = 0;
    int numLinks = 0;
    int maxSubs = 1;
    int numSubs = 0;
    int numKills = 0;
    int showMuted = 1;
    int expMuted;
    int l1 = 0;
    int l2 = 0;
    const char* inFn = NULL;
    const char* outFn = NULL;
    uint16_t killList[MAX_KILLS];
    int i;
    DPS_NodeAddress* listenAddr = NULL;

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
        if (IntArg("-k", &arg, &argc, &numKills, 0, MAX_KILLS)) {
            continue;
        }
        if (strcmp(*arg, "-m") == 0) {
            ++arg;
            showMuted = 0;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (*arg[0] == '-') {
            DPS_PRINT("Unknown option %s\n", arg[0]);
            return 1;
        }
        inFn = *arg++;
    }
    if (inFn) {
        numIds = ReadLinks(inFn);
        if (numIds == 0) {
            return 1;
        }
        DumpLinks();
    } else {
        DPS_PRINT("No input file\n");
        return 1;
    }
    /*
     * Mutex for protecting the link succes/fail counters
     */
    uv_mutex_init(&lock);
    /*
     * Start the nodes
     */
    for (i = 0; i < numIds; ++i) {
        DPS_Node* node = DPS_CreateNode("/.", NULL, NULL);
        /*
         * Set fast link monitor probes so we don't
         * need to wait so long to detect disconnects.
         */
        node->linkMonitorConfig = FastLinkProbe;
        /*
         * Since we set a fast link probe we need to set
         * a short subscription delay or link monitoring
         * will thrash.
         */
        node->subsRate = (FastLinkProbe.probeTO) / 4;

        listenAddr = DPS_CreateAddress();
        if (!listenAddr) {
            DPS_ERRPRINT("Failed to create address: %s\n", DPS_ErrTxt(DPS_ERR_RESOURCES));
            return 1;
        }
        DPS_SetAddress(listenAddr, "[::1]:0");
        ret = DPS_StartNode(node, DPS_FALSE, listenAddr);
        DPS_DestroyAddress(listenAddr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
        PortMap[GetPortNumber(node)] = NodeList[i];
        NodeMap[NodeList[i]] = node;
    }
    DumpPortMap(numIds);

    sleeper = DPS_CreateEvent();
    /*
     * Wait for a short time while before trying to link
     */
    DPS_TimedWaitForEvent(sleeper, 1000);
    /*
     * Link the nodes asynchronously
     */
    LinksUp = 0;
    LinksFailed = 0;
    for (l = links; l != NULL; l = l->next) {
        ret = LinkNodes(NodeMap[l->src], NodeMap[l->dst]);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to link nodes: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
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
#ifdef DPS_DEBUG
    {
        extern int _DPS_NumSubs;
        DPS_PRINT("Sent %d subs\n", _DPS_NumSubs);
        _DPS_NumSubs = 0;
    }
#endif
    DPS_PRINT("%d nodes created %d links \n", numIds, numLinks);
    /*
     * Add some subscriptions
     */
    while (maxSubs > 0) {
        for (i = 0; i < numIds && numSubs < maxSubs; ++i) {
            DPS_Node* node = NodeMap[NodeList[i]];
            if ((DPS_Rand() % 4) == 0) {
                DPS_Subscription* sub;
                char topic[] = "A";
                const char* topicList[] = { topic };

                topic[0] += DPS_Rand() % 26;
                sub = DPS_CreateSubscription(node, topicList, 1);
                if (!sub) {
                    DPS_ERRPRINT("CreateSubscribe failed\n");
                    break;
                }
                ret = DPS_Subscribe(sub, OnPubMatch);
                if (ret == DPS_OK) {
                    DPS_PRINT("Node %d is subscribing to \"%s\"\n", NodeList[i], topic);
                    SubsList[NodeList[i]] = 1;
                    ++numSubs;
                } else {
                    DPS_ERRPRINT("Subscribe failed %s\n", DPS_ErrTxt(ret));
                }
            }
        }
        /*
         * Need to have at least one subscription
         */
        if (numSubs > 0) {
            maxSubs = 0;
        }
    }
    /*
     * Decide which nodes we are going to kill
     */
    for (i = 0; i < numKills; ++i) {
        uint16_t goner = NodeList[DPS_Rand() % numIds];
        if (NodeMap[goner]) {
            killList[i] = goner;
        }
    }
    if (outFn) {
        dotFile = fopen(outFn, "w");
        if (!dotFile) {
            DPS_PRINT("Could not open %s for writing\n");
            dotFile = stdout;
        }
    }
    if (!dotFile) {
        dotFile = stdout;
    }
    /*
     * This will wait while links are being muted
     */
    expMuted = numLinks + 1 - numIds;
    WaitUntilSettled(sleeper, expMuted);

    if (DPS_Debug) {
        DumpMeshIds(numIds);
    }

    fprintf(dotFile, "graph {\n");
    fprintf(dotFile, "  node[shape=circle, width=0.3, fontsize=10, margin=\"0.01,0.01\", fixedsize=true];\n");
    fprintf(dotFile, "  overlap=false;\n");
    fprintf(dotFile, "  splines=true;\n");

    fprintf(dotFile, "subgraph cluster_1 {\n");
    fprintf(dotFile, "style=invis;\n");
    if (showMuted) {
        PrintSubgraph(dotFile, 1, killList, numKills, expMuted, "palegreen3", &l1);
    }
    PrintSubgraph(dotFile, 0, killList, numKills, expMuted, "palegreen", &l1);
    fprintf(dotFile, "}\n");

    if (numKills > 0) {
        int m;
        /*
         * Kill the nodes on the list
         */
        for (i = 0; i < numKills; ++i) {
            uint16_t goner = killList[i];
            DPS_Node* n = NodeMap[goner];
            if (n) {
                DPS_PRINT("Killing node %d (%d)\n", goner, GetPortNumber(n));
                DPS_DestroyNode(n, OnNodeDestroyed, &killList[i]);
                NodeMap[goner] = NULL;
            }
        }
        numLinks = MakeLinks(&numIds, &m);
        expMuted = numLinks + 1 - numIds;

        /*
         * This will wait while links are being unmuted
         */
        WaitUntilSettled(sleeper, expMuted);
        fprintf(dotFile, "subgraph cluster_2 {\n");
        fprintf(dotFile, "style=invis;\n");
        if (showMuted) {
            PrintSubgraph(dotFile, 1, NULL, 0, expMuted, "cadetblue3", &l2);
        }
        PrintSubgraph(dotFile, 0, NULL, 0, expMuted, "cadetblue1", &l2);
        fprintf(dotFile, "}\n");
    }

    fprintf(dotFile, "}\n");

    if (dotFile != stdout) {
        fclose(dotFile);
    }

    DPS_DestroyEvent(sleeper);

    for (i = 0; i < (int)A_SIZEOF(NodeMap); ++i) {
        if (NodeMap[i]) {
            DPS_DestroyNode(NodeMap[i], OnNodeDestroyed, NULL);
            NodeMap[i] = NULL;
        }
    }

    return 0;
}
