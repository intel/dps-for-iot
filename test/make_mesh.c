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
            if (remote->state == REMOTE_MUTED) {
                ++link->muted;
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
    *numMuted /= 2;
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
        " [color=black, len=1]",
        " [color=green, len=1]",
        " [color=red, style=dotted, len=2, weight=2]"
    };
    LINK* l;
    size_t i;
    int numNodes;
    int numArcs;
    int numMuted;
    int maxN = 0;

    numArcs = MakeLinks(&numNodes, &numMuted);
    DPS_PRINT("Nodes=%d, muted=%d\n", numNodes, numMuted);

    if (*label == 0) {
        *label = base + 1000;
        fprintf(f, "  %d[shape=none, width=1, style=bold, height=1, fontsize=12, label=\"nodes=%d\\narcs=%d\\nmuted=%d", *label, numNodes, numArcs, numMuted);
        if (expMuted != numMuted) {
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
        if (showMuted || (l->muted < 2)) {
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

static int HasUnstableLinks(void)
{
    size_t i;
    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        DPS_Node* node = NodeMap[i];
        if (node) {
            RemoteNode* remote;
            DPS_LockNode(node);
            for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
                /*
                 * These unstable states
                 */
                if (remote->state == REMOTE_LINKING || remote->state == REMOTE_UNLINKING) {
                    DPS_UnlockNode(node);
                    return DPS_TRUE;
                }
            }
            DPS_UnlockNode(node);
        }
    }
    return DPS_FALSE;
}

static int CountRemotes(DPS_Node* node, RemoteNodeState filter)
{
    int num = 0;

    if (node) {
        RemoteNode* remote;
        DPS_LockNode(node);
        for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
            uint16_t port = GetPort(&remote->ep.addr);
            uint16_t id = PortMap[port];
            /*
             * Ignore dead nodes
             */
            if (NodeMap[id] && remote->state == filter) {
                ++num;
            }
        }
        DPS_UnlockNode(node);
    }
    return num;
}

static int CountMutedLinks(void)
{
    int numMuted = 0;
    size_t i;

    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        numMuted += CountRemotes(NodeMap[i], REMOTE_MUTED);
    }
    return numMuted;
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
        int ep2 = 0;
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

static void DumpRemoteMeshIds(DPS_Node* node)
{
    RemoteNode* remote;

    DPS_LockNode(node);
    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        uint16_t port = GetPort(&remote->ep.addr);
        uint16_t id = PortMap[port];
        if (NodeMap[id]) {
            DPS_PRINT("    Node[%d] inbound.meshId=%s %s\n", id, DPS_UUIDToString(&remote->inbound.meshId), RemoteStateTxt(remote));
        }
    }
    DPS_UnlockNode(node);
}

static void DumpMeshIds(size_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        if (node) {
            DPS_LockNode(node);
            DPS_PRINT("Node[%d] meshId %s\n", id, DPS_UUIDToString(&node->meshId));
            DumpRemoteMeshIds(node);
            DPS_UnlockNode(node);
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

inline static void Swap(DPS_UUID** a, DPS_UUID** b)
{
    DPS_UUID* tmp = *a;
    *a = *b;
    *b = tmp;
}

static void UUIDSort(DPS_UUID** ids, int first, int last)
{
   if (first < last) {
      int pivot = first;
      int i = first;
      int j = last;

      while (i < j) {
         while (i < last && DPS_UUIDCompare(ids[i], ids[pivot]) < 0) {
            ++i;
         }
         while (DPS_UUIDCompare(ids[j], ids[pivot]) > 0) {
            --j;
         }
         if (i < j) {
            Swap(&ids[i], &ids[j]);
         }
      }
      Swap(&ids[pivot], &ids[j]);
      UUIDSort(ids, first, j - 1);
      UUIDSort(ids, j + 1, last);
   }
}

/* Generate a SED script to make debug output easier to read */
static void GenSedScript(FILE* sedFile, size_t numIds)
{
    DPS_UUID** meshIds = malloc(numIds * sizeof(DPS_UUID*));
    size_t numMeshIds = 0;
    size_t i;

    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        if (node) {
            meshIds[numMeshIds++] = &node->meshId;
            fprintf(sedFile, "s/\\[::1]:%d/Node[%d]/g\n", GetPortNumber(node), id);
        }
    }
    UUIDSort(meshIds, 0, (int)(numMeshIds - 1));
    for (i = 0; i < numMeshIds; ++i) {
        fprintf(sedFile, "s/%s/%d/g\n", DPS_UUIDToString(meshIds[i]), (int)i);
    }
    free(meshIds);
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_PRINT("Node %d destroyed\n", *(uint16_t*)data);
    }
}

static int subsRate = 250;
static int maxSettleTime;

static int WaitUntilSettled(DPS_Event* sleeper, size_t expMuted)
{
    int ret = 0;
    int i;
    size_t numMuted = 0;
    int repeats = 0;

    DPS_PRINT("Expect %d links muted\n", expMuted);

    /*
     * Wait until no nodes have links coming up or down or being unmuted
     */
    while (HasUnstableLinks()) {
        DPS_TimedWaitForEvent(sleeper, subsRate);
    }
    for (i = 0; i < maxSettleTime; i += subsRate) {
        numMuted = CountMutedLinks();
        if (numMuted == expMuted * 2) {
            /*
             * During link recovery the number of muted links can go down and then
             * go up again so we check that we get the same count mutiple times
             * before we concluding that things have settled.
             */
            if (++repeats == 5) {
                break;
            }
        } else {
            repeats = 0;
        }
        DPS_TimedWaitForEvent(sleeper, subsRate);
    }
    if (numMuted & 1) {
        DPS_PRINT("ERROR: expected even number of muted remotes\n");
        ret = 1;
    }
    /* Both ends of a link will be marked as muted, so divide the count by 2 */
    numMuted /= 2;
    if (numMuted != expMuted) {
        DPS_PRINT("ERROR: expected %d muted but got %d\n", expMuted, numMuted);
        ret = 1;
    }
    return ret;
}

static volatile int LinksUp;
static volatile int LinksFailed;

static uv_mutex_t lock;

static void OnLinked(DPS_Node* node, const DPS_NodeAddress* addr, DPS_Status status, void* data)
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

#define MAX_KILLS  16

static int IsListed(uint16_t* list, int len, int item)
{
    while (len--) {
        if (*list++ == item) {
            return DPS_TRUE;
        }
    }
    return DPS_FALSE;
}

int main(int argc, char** argv)
{
    int err = 0;
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
    int allSubs = 0;
    int l1 = 0;
    int l2 = 0;
    const char* inFn = NULL;
    const char* outFn = NULL;
    const char* sedFn = NULL;
    uint16_t killList[MAX_KILLS];
    int i;
    int debugKills = 0;
    DPS_NodeAddress* listenAddr = NULL;

    DPS_Debug = 0;

    while (--argc) {
        if (StrArg("-f", &arg, &argc, &inFn)) {
            continue;
        }
        if (StrArg("-o", &arg, &argc, &outFn)) {
            continue;
        }
        if (StrArg("-e", &arg, &argc, &sedFn)) {
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
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            allSubs = 1;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (strcmp(*arg, "-dk") == 0) {
            ++arg;
            debugKills = 1;
            continue;
        }
        if (*arg[0] == '-') {
            DPS_PRINT("Unknown option %s\n", arg[0]);
            DPS_PRINT("%s [-f <mesh file>] [-o <file>] [-m] [-d] [-s <max subs>] [-k <max kills>] [-a]\n");
            DPS_PRINT("options\n");
            DPS_PRINT("    -a  all nodes subscribe to the same topic\n");
            DPS_PRINT("    -d  enable debug output\n");
            DPS_PRINT("    -f  specifies the input file describing the mesh\n");
            DPS_PRINT("    -k  maximum number of randomly terminated links\n");
            DPS_PRINT("    -m  hide muted arcs in the graph\n");
            DPS_PRINT("    -o  specifies the output file for the graph (graphviz format)\n");
            DPS_PRINT("    -e  generate a sed script to process debug output\n");
            DPS_PRINT("    -s  maximum number of subscriptions\n");
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
     * Time to wait for the mesh to stabilize
     */
    maxSettleTime = 1000 + numIds * subsRate * 10;
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
         * Set short subscription delay to speed up the test case
         */
        node->subsRate = subsRate;
        /*
         * Set link-loss timer to multiple of subscription delay so
         * disconnects are detected quickly.
         */
        node->linkLossTimeout = 10 * node->subsRate;

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
    DumpMeshIds(numIds);

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
    DumpMeshIds(numIds);
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
    if (allSubs) {
        maxSubs = numIds;
    }
    while (maxSubs > 0) {
        for (i = 0; i < numIds && numSubs < maxSubs; ++i) {
            DPS_Node* node = NodeMap[NodeList[i]];
            if (allSubs || ((DPS_Rand() % 4) == 0)) {
                DPS_Subscription* sub;
                char topic[] = "A";
                const char* topicList[] = { topic };

                if (!allSubs) {
                    topic[0] += DPS_Rand() % 26;
                }
                sub = DPS_CreateSubscription(node, topicList, 1);
                if (!sub) {
                    DPS_ERRPRINT("CreateSubscribe failed\n");
                    break;
                }
                DPS_PRINT("Calling DPS_Subscribe for node %d\n", i);
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
    if (sedFn) {
        FILE* sedFile = fopen(sedFn, "w");
        if (!sedFile) {
            DPS_PRINT("Could not open %s for writing\n");
        } else {
            GenSedScript(sedFile, numIds);
            fclose(sedFile);
        }
    }
    /*
     * This will wait while links are being muted
     */
    expMuted = numLinks + 1 - numIds;
    err = WaitUntilSettled(sleeper, expMuted);

    DumpMeshIds(numIds);

    if (numKills > 0) {
        int maxKills = 0;
        /*
         * Only consider nodes with more than one active link
         */
        for (i = 0; i < numIds; ++i) {
            DPS_Node* node = NodeMap[NodeList[i]];
            if (CountRemotes(node, REMOTE_ACTIVE) > 1) {
                DPS_PRINT("Kill candidate %d\n", NodeList[i]);
                ++maxKills;
            }
        }
        if (maxKills < numKills) {
            numKills = maxKills;
        }
        DPS_PRINT("Killing %d nodes\n", numKills);
        memset(killList, 0xFF, sizeof(killList));
        for (i = 0; i < numKills; ++i) {
            uint16_t goner;
            do {
                goner = NodeList[DPS_Rand() % numIds];
            } while (IsListed(killList, numKills, goner) || CountRemotes(NodeMap[goner], REMOTE_ACTIVE) < 2);
            killList[i] = goner;
        }
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

        if (debugKills) {
            DPS_Debug = 1;
        }
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
         * Increase the max settle time for the recovery
         */
        maxSettleTime *= 8;
        /*
         * This will wait while links are being unmuted
         */
        err = WaitUntilSettled(sleeper, expMuted);

        DumpMeshIds(numIds);

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

    return err;
}
