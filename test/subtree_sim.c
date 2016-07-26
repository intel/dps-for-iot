#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <dps.h>
#include <bitvec.h>
#include <topics.h>
#include <search.h>
#include <uv.h>

DPS_Status DPS_BitVectorPermute(DPS_BitVector* perm, DPS_BitVector* bv);



static int verbose = 0;
static int infixWildcards = 0;

struct {
    int numMatches;
    int falsePositives;
    int totalSubs;
    int numNodes;
    int numPubs;
    int numMsgs;
} totals;

static size_t uniqueSubscriptionTopics;

static char lineBuf[200];

#define MAX_PUB_TOPICS     8
#define NUM_PUB_FORMATS    7


static const char* pubFormats[NUM_PUB_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/%d/%d"
};

#define MAX_SUB_TOPICS        8  /* Max topics per subscription */
#define NUM_SUB_FORMATS       9
#define FIRST_INFIX_WILDCARD  6  /* First format string with infix wild card */

static const char* subFormats[NUM_SUB_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/#",
    "%d/#",
    /* infix wildcards last so can be optionally excluded */
    "%d/%d/+/%d",
    "%d/+/%d/+/%d",
    "%d/+/%d"
};

static void PrintTopics(const char* label, char* topics[], size_t num)
{
    DPS_PRINT("%s: ", label);
    if (num) {
        while (num--) {
            DPS_PRINT("%s%s", *topics++, num ? " & " : "\n");
        }
    } else {
        DPS_PRINT("\n");
    }
}

static void FreeTopics(char* topics[], size_t num)
{
    while (num--) {
        free(topics[num]);
    }
}

static const char* UniqueSubTopic = "foo/bar/hello/world";
static const char* UniquePubTopic = "foo/bar/hello/world";
static int uniqueSub = 0;


static size_t InitRandomSub(DPS_BitVector* bv, char* topics[])
{
    DPS_Status ret;
    size_t i = 0;
    size_t numSubs;
    ENTRY addEntry;
    ENTRY* foundEntry;

    DPS_BitVectorClear(bv);

    if (uniqueSub) {
        uniqueSub = 0;
        topics[0] = strdup(UniqueSubTopic);
        ret = DPS_AddTopic(bv, topics[0], "/.", DPS_Sub);
        assert(ret == DPS_OK);
        return 1;
    }

    numSubs = 1 + (random() % (MAX_SUB_TOPICS - 1));
    while (i < numSubs) {
        int fmt = random() % NUM_SUB_FORMATS;
        if (fmt < FIRST_INFIX_WILDCARD || infixWildcards) {
            int a = random() % 10;
            int b = random() % 10;
            int c = random() % 10;
            int d = random() % 10;
            topics[i] = malloc(32);
            sprintf(topics[i], subFormats[fmt], a, b, c, d);
            ret = DPS_AddTopic(bv, topics[i], "/.", DPS_Sub);
            assert(ret == DPS_OK);
            /*
             * Use hash table to track unique subscription topics
             */
            addEntry.key = topics[i];
            addEntry.data = topics[i];
            foundEntry = hsearch(addEntry, ENTER);
            assert(foundEntry);
            if (foundEntry->data == topics[i]) {
                ++uniqueSubscriptionTopics;
            }
            foundEntry->data = NULL;
            ++i;
        }
    }
    return numSubs;
}

static size_t InitRandomPub(DPS_BitVector* bv, char* topics[])
{
    DPS_Status ret;
    size_t i;
    size_t numPubs = 1 + (random() % (MAX_PUB_TOPICS - 1));

    DPS_BitVectorClear(bv);

    for (i = 0; i < numPubs; ++i) {
        /*
         * Build a random node
         */
        int fmt = random() % NUM_PUB_FORMATS;
        int a = random() % 8;
        int b = random() % 6;
        int c = random() % 5;
        int d = random() % 4;
        int e = random() % 50;
        topics[i] = malloc(32);
        sprintf(topics[i], pubFormats[fmt], a, b, c, d, e);
        ret = DPS_AddTopic(bv, topics[i], "/.", DPS_Pub);
        assert(ret == DPS_OK);
    }
    return numPubs;
}

#define MIN(x, y)  ((x) < (y) ? (x) : (y))

#define MAX_CHILDREN 10

typedef struct _SubNode {
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    char* strings[MAX_SUB_TOPICS];
    size_t count;
    uint32_t revision;
    int expect;
    int falsePositives;
    int numMatches;
    int totalSubs;
    size_t numChildren;
    struct _SubNode* child[1];
} SubNode;

#define MAX_TREE_DEPTH 8

#define MIN(x, y)  ((x) < (y) ? (x) : (y))

static size_t trueTrace[MAX_TREE_DEPTH + 1];
static size_t falseTrace[MAX_TREE_DEPTH + 1];
static size_t numNodes[MAX_TREE_DEPTH + 1];
static size_t rejectByNeeds[MAX_TREE_DEPTH + 1];
static size_t rejectByPop[MAX_TREE_DEPTH + 1];
static size_t staleMessages[MAX_TREE_DEPTH + 1];
static size_t totalMessages[MAX_TREE_DEPTH + 1];

#define MESH_LAYERS   7

static size_t MaxLayerSizes[MESH_LAYERS] = { 50, 100, 500, 100, 50, 10, 500 };

SubNode* AllocNode(size_t numChildren)
{
    SubNode* node = calloc(1, sizeof(SubNode) + numChildren * sizeof(SubNode*));

    node->numChildren = numChildren;
    node->interests = DPS_BitVectorAlloc();
    node->needs = DPS_BitVectorAllocPerm();
    return node;
}

static SubNode* BuildMesh()
{
    SubNode* root;
    SubNode** layers[MESH_LAYERS];
    size_t layerSize[MESH_LAYERS];
    int i;
    int l;
    int c;

    /*
     * Size and allocate the layers
     */
    for (i = 0; i < MESH_LAYERS; ++i) {
        SubNode** layer;
        layerSize[i] = 1 + random() % MaxLayerSizes[i];
        DPS_PRINT("Build layer %d - size=%d\n", i, layerSize[i]);
        layer = calloc(1, layerSize[i] * sizeof(SubNode*));
        layers[i] = layer;
    }
    root = AllocNode(layerSize[0]);
    for (c = 0; c < layerSize[0]; ++c) {
        SubNode* node = AllocNode(1 + random() % (1 + layerSize[0] / 10));
        root->child[c] = layers[0][c] = node;
    }
    /*
     * Link nodes at each layer to a set of nodes from the layer above
     */
    for (i = 0; i < (MESH_LAYERS - 1); ++i) {
        SubNode** layer = layers[i];
        SubNode** upper = layers[i + 1];
        size_t upperSize = layerSize[i + 1];
        for (l = 0; l < layerSize[i]; ++l) {
            SubNode* node = layer[l];
            if (!node) {
                continue;
            }
            for (c = 0; c < node->numChildren; ++c) {
                int n = random() % upperSize;
                if (!upper[n]) {
                    if (i == (MESH_LAYERS - 2)) {
                        upper[n] = AllocNode(0);
                    } else {
                        upper[n] = AllocNode(1 + random() % (1 + layerSize[i + 2] / 10));
                    }
                }
                node->child[c] = upper[n];
            }
        }
    }
    for (i = 0; i < MESH_LAYERS; ++i) {
        SubNode** layer = layers[i];
        numNodes[i] = 0;
        for (l = 0; l < layerSize[i]; ++l) {
            if (layer[l]) {
                ++numNodes[i];
                ++totals.numNodes;
            }
        }
        DPS_PRINT("Layer %d - actual nodes=%d\n", i, numNodes[i]);
    }
    return root;
}

static SubNode* BuildTree(int depth)
{
    size_t i;
    SubNode* node;

    if (depth > 0) {
        int numChildren = 1 + random() % MAX_CHILDREN;
        node = calloc(1, sizeof(SubNode) + sizeof(struct _SubNode*) * (numChildren - 1));
        for (i = 0; i < numChildren; ++i) {
            node->child[i] = BuildTree(depth - 1);
        }
        node->numChildren = numChildren;
    } else {
        node = calloc(1, sizeof(SubNode));
    }
    ++numNodes[depth];
    ++totals.numNodes;
    node->interests = DPS_BitVectorAlloc();
    node->needs = DPS_BitVectorAllocPerm();
    return node;
}

static void FreeTree(SubNode* node)
{
    size_t c = node->numChildren;
    node->numChildren = 0;
    while (c--) {
        FreeTree(node->child[c]);
    }
    DPS_BitVectorFree(node->interests);
    DPS_BitVectorFree(node->needs);
    free(node);
}

static void ShowTree(SubNode* node, int depth, int topics)
{
    char in[64];

    memset(in, node->expect ? '+' : '-', depth * 2);
    in[depth * 2] = 0;
    if (node->numChildren > 0) {
        size_t i;
        DPS_PRINT("%s%d  (%p)\n", in, node->numChildren, node);
        for (i = 0; i < node->numChildren; ++i) {
            ShowTree(node->child[i], depth + 1, topics);
        }
    } else {
        if (topics) {
            PrintTopics(in, node->strings, node->count);
        }
    }
}

static void ClearExpects(SubNode* node)
{
    if (node->expect) {
        size_t i;
        node->expect = 0;
        for (i = 0; i < node->numChildren; ++i) {
            ClearExpects(node->child[i]);
        }
    }
}

static void CleanTree(SubNode* node)
{
    size_t i;
    for (i = 0; i < node->numChildren; ++i) {
        CleanTree(node->child[i]);
    }
    if (node->count) {
        FreeTopics(node->strings, node->count);
        node->count = 0;
    }
}

DPS_BitVector* permChecker;

static void PopulateTree(SubNode* node)
{
    if (node->numChildren == 0) {
        if (!node->count) {
            node->count = InitRandomSub(node->interests, node->strings);
            DPS_BitVectorPermute(node->needs, node->interests);
            DPS_BitVectorIntersection(permChecker, permChecker, node->needs);
            DPS_BitVectorDump(node->needs, 1);
            DPS_BitVectorDump(permChecker, 1);
            node->totalSubs += node->count;
            totals.totalSubs += node->count;
        }
    } else {
        size_t i;
        DPS_BitVectorClear(node->interests);
        DPS_BitVectorFill(node->needs);
        for (i = 0; i < node->numChildren; ++i) {
            PopulateTree(node->child[i]);
            DPS_BitVectorUnion(node->interests, node->child[i]->interests);
            DPS_BitVectorIntersection(node->needs, node->needs, node->child[i]->needs);
        }
    }
}

static int SetExpects(SubNode* node, char** pubs, size_t numPubs)
{
    if (node->expect) {
        return 0;
    }
    if (node->numChildren == 0) {
        DPS_MatchTopicList(pubs, numPubs, node->strings, node->count, "/.", &node->expect);
    } else {
        size_t i;
        for (i = 0; i < node->numChildren; ++i) {
            node->expect += SetExpects(node->child[i], pubs, numPubs);
        }
    }
    return node->expect;
}

static int PropagatePub(SubNode* node, DPS_BitVector* pub, uint32_t revision, int depth)
{
    int numMatches = 0;
    DPS_Status ret;

    ++totalMessages[depth];
    /*
     * Ignore if we have already seen this publication. This is equivalent to the check in dps.c
     */
    if (revision <= node->revision) {
        ++staleMessages[depth];
        return 0;
    }
    node->revision = revision;

    if (node->numChildren == 0) {
        if (DPS_BitVectorIncludes(pub, node->interests)) {
            if (node->expect) {
                ++node->numMatches;
                ++totals.numMatches;
                numMatches = 1;
            } else {
                ++node->falsePositives;
                ++totals.falsePositives;
            }
        } else {
            if (node->expect) {
                DPS_PRINT("FAILURE!!! False negative at child\n");
            }
        }
    } else {
        size_t i;
        DPS_BitVector* provides = DPS_BitVectorAllocPerm();
        DPS_BitVector* tmp = DPS_BitVectorAlloc();
        for (i = 0; i < node->numChildren; ++i) {
            int match;
            SubNode* child = node->child[i];
            /*
             * Duplicates match logic from dps.c
             */
            ret = DPS_BitVectorIntersection(tmp, pub, child->interests);
            assert(ret == DPS_OK);
            if (child->numChildren == 0) {
                match = DPS_BitVectorEquals(tmp, child->interests);
            } else {
                ret = DPS_BitVectorPermute(provides, tmp);
                assert(ret == DPS_OK);
                match = DPS_BitVectorIncludes(provides, child->needs);
            }
            if (match) {
                if (child->expect) {
                    ++trueTrace[depth + 1];
                } else {
                    ++falseTrace[depth + 1];
                }
                ++totals.numMsgs;
                numMatches += PropagatePub(child, tmp, revision, depth + 1);
            } else {
                ++rejectByNeeds[depth];
                if (child->expect) {
                    DPS_PRINT("FAILURE!!! False negative\n");
                }
            }
        }
        DPS_BitVectorFree(tmp);
    }
    return numMatches;
}

#define NUM_REPLACEMENTS 1

static void RunSimulation(int runs, int depth, int pubIters)
{
    DPS_Status ret;
    int mesh = (depth == 0);
    int i;
    int r;
    DPS_BitVector* pub = DPS_BitVectorAlloc();
    SubNode fakeRoot;
    SubNode* subscriptions;
    int minMsgs = 0;
    float maxLoad = 0.0;
    float totalLoad = 0.0;
    uint32_t revision = 0;

    if (mesh) {
        subscriptions = BuildMesh();
        depth = MESH_LAYERS;
    } else {
        subscriptions = BuildTree(depth);
    }

    memset(&fakeRoot, 0, sizeof(fakeRoot));
    fakeRoot.numChildren = 1;
    fakeRoot.child[0] = subscriptions;

#if 0
    hcreate(totals.numNodes * MAX_SUB_TOPICS);
    PopulateTree(subscriptions);
    hdestroy();
    ShowTree(subscriptions, 0);
#endif

    permChecker = DPS_BitVectorAllocPerm();
    for (r = 0; r < runs; ++r) {
        char* pubTopics[MAX_PUB_TOPICS];
        int expects;
        int actuals;
        float lf;
        int p;
        /*
         * Hash table for subscription topic counting
         */
        hcreate(totals.numNodes * MAX_SUB_TOPICS);
        /*
         * Build a tree of random subscriptions.
         */
        if (pubIters == 0) {
            uniqueSub = 1;
        }
        DPS_BitVectorFill(permChecker);
        PopulateTree(subscriptions);
        DPS_BitVectorDump(permChecker, 1);
        /*
         * Done with the hash table
         */
        hdestroy();

        lf = DPS_BitVectorLoadFactor(subscriptions->interests);
        if (lf > maxLoad) {
            maxLoad = lf;
        }
        totalLoad += lf;
        /*
         * Tests random publications against the subscriptions
         */
        for (p = 0; p < pubIters; ++p) {
            size_t numPubTopics = InitRandomPub(pub, pubTopics);
            /*
             * Identify expected matches
             */
            ClearExpects(subscriptions);
            expects = SetExpects(subscriptions, pubTopics, numPubTopics);
            //ShowTree(subscriptions, 0, 0);
            /*
             * Propagate the publication up the tree
             */
            actuals = PropagatePub(&fakeRoot, pub, ++revision, -1);
            if (actuals != expects) {
                DPS_ERRPRINT("Expects=%d actuals=%d\n", expects, actuals);

            }
            FreeTopics(pubTopics, numPubTopics);
            ++totals.numPubs;
        }
        /*
         * Sends a single publication
         */
        if (pubIters == 0) {
            size_t numPubTopics = 1;

            pubTopics[0] = strdup(UniquePubTopic);
            DPS_BitVectorClear(pub);
            DPS_AddTopic(pub, pubTopics[0], "/.", DPS_Pub);

            ClearExpects(subscriptions);
            expects = SetExpects(subscriptions, pubTopics, numPubTopics);
            //ShowTree(subscriptions, 0, 0);

            actuals = PropagatePub(&fakeRoot, pub, ++revision, -1);
            if (actuals != expects) {
                DPS_ERRPRINT("Expects=%d actuals=%d\n", expects, actuals);
            }
            FreeTopics(pubTopics, numPubTopics);
            ++totals.numPubs;
        }
        /*
         * Done with these subscriptions
         */
        CleanTree(subscriptions);
    }
    DPS_BitVectorFree(pub);
    //FreeTree(subscriptions);

    minMsgs = 0;
    for (i = 0; i <= depth; ++i) {
        minMsgs += trueTrace[i];
    }

    DPS_PRINT("Message efficiency=%2.2f%%\n", (float)(minMsgs * 100) / (float)(totals.numMsgs));
    DPS_PRINT("Nodes=%d, pubs=%d, actual msgs=%d, min msgs=%d\n", totals.numNodes, totals.numPubs, totals.numMsgs, minMsgs);
    DPS_PRINT("Max load at root=%2.3f%%, Avg load at root=%2.3f%%\n", maxLoad, totalLoad / runs);
    DPS_PRINT("Matched publications=%d, false positives=%d\n", totals.numMatches, totals.falsePositives);
    DPS_PRINT("Unique subscription topic strings=%d (out of %d total)\n", uniqueSubscriptionTopics, totals.totalSubs);

    DPS_PRINT("Node count:            ");
    if (mesh) {
        DPS_PRINT(" %7d ", 1);
        for (i = 0; i < depth; ++i) {
            DPS_PRINT(" %7d ", numNodes[i]);
        }
    } else {
        for (i = depth; i >= 0; --i) {
            DPS_PRINT(" %7d ", numNodes[i]);
        }
    }
    DPS_PRINT("\n");

    DPS_PRINT("Total messages:        ");
    for (i = 0; i <= depth; ++i) {
        DPS_PRINT(" %7d ", totalMessages[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("True propagations:     ");
    for (i = 0; i <= depth; ++i) {
        DPS_PRINT(" %7d ", trueTrace[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("False propagations:    ");
    for (i = 0; i <= depth; ++i) {
        DPS_PRINT(" %7d ", falseTrace[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("Reject by needs check: ");
    for (i = 0; i <= depth; ++i) {
        DPS_PRINT(" %7d ", rejectByNeeds[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("Blocked stale messages:");
    for (i = 0; i <= depth; ++i) {
        DPS_PRINT(" %7d ", staleMessages[i]);
    }
    DPS_PRINT("\n\n");
}

static int IntArg(char* opt, char*** argp, int* argcp, int* val, uint32_t min, uint32_t max)
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
    int bitLen = 1024 * 32;
    int runs = 100;
    int depth = 4;
    int hashes = 4;
    int seed = 0;
    int pubs = 100;
    DPS_Status ret;
    int numArgs = argc;
    char** arg = argv + 1;

    DPS_Debug = 0;

    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (strcmp(*arg, "-v") == 0) {
            ++arg;
            verbose = 1;
            continue;
        }
        if (strcmp(*arg, "-i") == 0) {
            ++arg;
            infixWildcards = 1;
            continue;
        }
        if (IntArg("-t", &arg, &argc, &depth, 0, MAX_TREE_DEPTH)) {
            continue;
        }
        if (IntArg("-r", &arg, &argc, &runs, 1, 100000)) {
            continue;
        }
        if (IntArg("-k", &arg, &argc, &bitLen, 1, 1024)) {
            bitLen *= 1024;
            continue;
        }
        if (IntArg("-h", &arg, &argc, &hashes, 2, 16)) {
            continue;
        }
        if (IntArg("-b", &arg, &argc, &bitLen, 64, 8 * 1024 * 1024)) {
            continue;
        }
        if (IntArg("-s", &arg, &argc, &seed, 0, UINT32_MAX)) {
            continue;
        }
        if (IntArg("-p", &arg, &argc, &pubs, 0, UINT32_MAX)) {
            continue;
        }
        if (IntArg("-s", &arg, &argc, &seed, 0, UINT32_MAX)) {
            continue;
        }
        if (IntArg("-p", &arg, &argc, &pubs, 0, UINT32_MAX)) {
            continue;
        }
        goto Usage;
    }

    if (seed) {
        srandom(seed);
    } else {
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        srandom(t.tv_nsec);
    }

    if (DPS_Configure(bitLen, hashes) != DPS_OK) {
        DPS_PRINT("Invalid configuration parameters\n");
        return 1;
    }

    while (numArgs--) {
        DPS_PRINT("%s ", *argv);
        ++argv;
    }

    DPS_PRINT("\n\nBit length=%d (%d bytes)\n", bitLen, bitLen / 8);

    RunSimulation(runs, depth, pubs);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-i] [-v] [-t <tree depth>] [b <bits> | -k <kbits>] [-r <runs>] [-d]\n", *argv);
    DPS_PRINT("      -i   Enable infix wildcards\n");
    DPS_PRINT("      -v   Verbose\n");
    DPS_PRINT("      -d   Debugging\n");
    return 1;
}
