#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <dps.h>
#include <bitvec.h>
#include <topics.h>
#include <uv.h>


static int verbose = 0;
static int infixWildcards = 0;

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
#ifdef DPS_MQTT_LIKE
    "%d/%d/%d/#",
    "%d/#",
    /* infix wildcards last so can be optionally excluded */
    "%d/%d/+/%d",
    "%d/+/%d/+/%d",
    "%d/+/%d"
#else
    "%d/%d/%d/*",
    "%d/*",
    /* infix wildcards last so can be optionally excluded */
    "%d/%d/*/%d",
    "%d/*/%d/*/%d",
    "%d/*/%d"
#endif
};

static void PrintTopics(const char* label, char* topics[], size_t num)
{
    DPS_PRINT("%s: ", label);
    while (num--) {
        DPS_PRINT("%s%s", *topics++, num ? " & " : "\n");
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


static size_t InitRandomSub(DPS_BitVector* bv, char* topics[])
{
    DPS_Status ret;
    size_t i = 0;
    size_t numSubs = 1 + (random() % (MAX_SUB_TOPICS - 1));

    DPS_BitVectorClear(bv);

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

#define MAX_LEAFS 10

typedef struct _SubNode {
    DPS_BitVector* interests;
    uint64_t needs;
    size_t pop;
    char* strings[MAX_SUB_TOPICS];
    size_t count;
    int expect;
    int falsePositives;
    int numMatches;
    int totalSubs;
    size_t numLeafs;
    struct _SubNode* leaf[1];
} SubNode;

#define MAX_TREE_DEPTH 8

#define MIN(x, y)  ((x) < (y) ? (x) : (y))

static size_t trueTrace[MAX_TREE_DEPTH + 1];
static size_t falseTrace[MAX_TREE_DEPTH + 1];
static size_t numNodes[MAX_TREE_DEPTH + 1];
static size_t rejectByNeeds[MAX_TREE_DEPTH + 1];
static size_t rejectByPop[MAX_TREE_DEPTH + 1];
static size_t totalMsgs;

static SubNode* BuildTree(int depth)
{
    size_t i;
    SubNode* node;

    if (depth > 0) {
        int numLeafs = 1 + random() % MAX_LEAFS;
        node = calloc(1, sizeof(SubNode) + sizeof(struct _SubNode*) * (numLeafs - 1));
        for (i = 0; i < numLeafs; ++i) {
            node->leaf[i] = BuildTree(depth - 1);
        }
        node->numLeafs = numLeafs;
    } else {
        node = calloc(1, sizeof(SubNode));
    }
    ++numNodes[depth];
    node->interests = DPS_BitVectorAlloc();
    return node;
}

static void FreeTree(SubNode* node)
{
    size_t i;
    for (i = 0; i < node->numLeafs; ++i) {
        FreeTree(node->leaf[i]);
    }
    DPS_BitVectorFree(node->interests);
    free(node);
}

static void ShowTree(SubNode* node, int depth)
{
    char in[64];

    memset(in, node->expect ? '+' : '-', depth * 2);
    in[depth * 2] = 0;
    if (node->numLeafs > 0) {
        size_t i;
        DPS_PRINT("%s%d\n", in, node->numLeafs);
        for (i = 0; i < node->numLeafs; ++i) {
            ShowTree(node->leaf[i], depth + 1);
        }
    } else {
        PrintTopics(in, node->strings, node->count);
    }
}

static void ReplaceSubscription(SubNode* node, const char* topicString)
{
    if (node->numLeafs) {
        size_t i = random() % node->numLeafs;
        ReplaceSubscription(node->leaf[i], topicString);
        /*
         * Need to rebuild the bit vector
         */
        DPS_BitVectorClear(node->interests);
        node->needs = ~0ull;
        node->pop = UINT32_MAX;
        for (i = 0; i < node->numLeafs; ++i) {
            DPS_BitVectorUnion(node->interests, node->leaf[i]->interests);
            node->needs &= node->leaf[i]->needs;
            node->pop = MIN(node->pop, node->leaf[i]->pop);
        }
    } else {
        DPS_BitVectorClear(node->interests);
        FreeTopics(node->strings, node->count);
        node->strings[0] = strdup(topicString);
        node->count = 1;
        DPS_AddTopic(node->interests, node->strings[0], "/.", DPS_Sub);
        node->pop = DPS_BitVectorSquash(node->interests, &node->needs);
    }
}

static void CleanTree(SubNode* node)
{
    size_t i;
    for (i = 0; i < node->numLeafs; ++i) {
        CleanTree(node->leaf[i]);
    }
    FreeTopics(node->strings, node->count);
}

static void PopulateTree(SubNode* node)
{
    if (node->numLeafs == 0) {
        node->count = InitRandomSub(node->interests, node->strings);
        node->pop = DPS_BitVectorSquash(node->interests, &node->needs);
        node->totalSubs += node->count;
    } else {
        size_t i;
        DPS_BitVectorClear(node->interests);
        node->needs = ~0ull;
        node->pop = UINT32_MAX;
        for (i = 0; i < node->numLeafs; ++i) {
            PopulateTree(node->leaf[i]);
            DPS_BitVectorUnion(node->interests, node->leaf[i]->interests);
            node->needs &= node->leaf[i]->needs;
            node->pop = MIN(node->pop, node->leaf[i]->pop);
            assert(node->pop);
        }
    }
}

static int SetExpects(SubNode* node, char** pubs, size_t numPubs)
{
    if (node->numLeafs == 0) {
        DPS_MatchTopicList(pubs, numPubs, node->strings, node->count, "/.", &node->expect);
    } else {
        size_t i;
        node->expect = 0;
        for (i = 0; i < node->numLeafs; ++i) {
            node->expect |= SetExpects(node->leaf[i], pubs, numPubs);
        }
    }
    return node->expect;
}

static void PropagatePub(SubNode* node, DPS_BitVector* pub, int depth)
{
    DPS_Status ret;

    if (node->numLeafs == 0) {
        if (DPS_BitVectorIncludes(pub, node->interests)) {
            if (node->expect) {
                ++node->numMatches;
            } else {
                ++node->falsePositives;
            }
        } else {
            if (node->expect) {
                DPS_PRINT("FAILURE!!! False negative at leaf\n");
            }
        }
    } else {
        size_t i;
        DPS_BitVector* tmp = DPS_BitVectorAlloc();
        for (i = 0; i < node->numLeafs; ++i) {
            SubNode* leaf = node->leaf[i];
            uint64_t provides;
            size_t pop;
            /*
             * Duplicates match logic from dps.c
             */
            ret = DPS_BitVectorIntersection(tmp, pub, leaf->interests);
            assert(ret == DPS_OK);
            pop = DPS_BitVectorSquash(tmp, &provides);
            if ((pop >= leaf->pop) && ((provides & leaf->needs) == leaf->needs)) {
                if (leaf->expect) {
                    ++trueTrace[depth + 1];
                } else {
                    ++falseTrace[depth + 1];
                }
                ++totalMsgs;
                PropagatePub(leaf, tmp, depth + 1);
            } else {
                if (pop < leaf->pop) {
                    ++rejectByPop[depth];
                } else {
                    ++rejectByNeeds[depth];
                }
                if (leaf->expect) {
                    DPS_PRINT("FAILURE!!! False negative\n");
                }
            }
        }
        DPS_BitVectorFree(tmp);
    }
}

typedef struct {
    int numMatches;
    int falsePositives;
    int totalSubs;
    int numNodes;
} Stats;

static void Analyze(SubNode* node, Stats* stats)
{
    size_t i;

    ++stats->numNodes;
    stats->numMatches += node->numMatches;
    stats->falsePositives += node->falsePositives;
    stats->totalSubs += node->totalSubs;
    for (i = 0; i < node->numLeafs; ++i) {
        Analyze(node->leaf[i], stats);
    }
}

#define NUM_REPLACEMENTS 1

static void RunSimulation(int runs, int treeDepth, int pubIters)
{
    DPS_Status ret;
    int i;
    int r;
    DPS_BitVector* pub = DPS_BitVectorAlloc();
    SubNode fakeRoot;
    SubNode* subscriptions;
    int numPubs = 0;
    int minMsgs = 0;
    Stats stats;
    float maxLoad = 0.0;
    float totalLoad = 0.0;

    subscriptions = BuildTree(treeDepth);

    fakeRoot.numLeafs = 1;
    fakeRoot.leaf[0] = subscriptions;

#if 0
    PopulateTree(subscriptions);
    ShowTree(subscriptions, 0);
#endif

    for (r = 0; r < runs; ++r) {
        float lf;
        int p;
        /*
         * Build a tree of random subscriptions.
         */
        PopulateTree(subscriptions);
        lf = DPS_BitVectorLoadFactor(subscriptions->interests);
        if (lf > maxLoad) {
            maxLoad = lf;
        }
        totalLoad += lf;

        /*
         * Tests random publications against the subscriptions
         */
        for (p = 0; p < pubIters; ++p) {
            char* pubTopics[MAX_PUB_TOPICS];
            size_t numPubTopics = InitRandomPub(pub, pubTopics);
            /*
             * Identify expected matches
             */
            SetExpects(subscriptions, pubTopics, numPubTopics);
            /*
             * Propagate the publication up the tree
             */
            DPS_BitVectorDump(pub, 0);
            PropagatePub(&fakeRoot, pub, -1);
            FreeTopics(pubTopics, numPubTopics);
            ++numPubs;
        }
        /*
         * Sends a single publication
         */
        if (pubIters == 0) {
            size_t n;
            char* pubTopics[MAX_PUB_TOPICS];
            size_t numPubTopics = 1;

            pubTopics[0] = strdup(UniquePubTopic);
            DPS_BitVectorClear(pub);
            DPS_AddTopic(pub, pubTopics[0], "/.", DPS_Pub);
            for (n = 0; n < NUM_REPLACEMENTS; ++n) {
                ReplaceSubscription(subscriptions, UniqueSubTopic);
            }
            /*
             * Identify expected matches
             */
            SetExpects(subscriptions, pubTopics, numPubTopics);
            FreeTopics(pubTopics, numPubTopics);
            PropagatePub(&fakeRoot, pub, -1);
            ++numPubs;
        }
        /*
         * Done with these subscriptions
         */
        CleanTree(subscriptions);
    }
    DPS_BitVectorFree(pub);

    memset(&stats, 0, sizeof(stats));
    Analyze(subscriptions, &stats);
    FreeTree(subscriptions);

    minMsgs = 0;
    for (i = 0; i <= treeDepth; ++i) {
        minMsgs += trueTrace[i];
    }

    DPS_PRINT("Message efficiency=%2.2f%%\n", (float)(minMsgs * 100) / (float)(totalMsgs));
    DPS_PRINT("Nodes=%d, pubs=%d, actual msgs=%d, min msgs=%d\n", stats.numNodes, numPubs, totalMsgs, minMsgs);
    DPS_PRINT("Max load at root=%2.3f%%, Avg load at root=%2.3f%%\n", maxLoad, totalLoad / runs);
    DPS_PRINT("Subs=%d, Matches=%d, false positives=%d\n", stats.totalSubs, stats.numMatches, stats.falsePositives);

    DPS_PRINT("Node count:           ");
    for (i = treeDepth; i >= 0; --i) {
        DPS_PRINT(" %7d ", numNodes[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("True propagations:    ");
    for (i = 0; i <= treeDepth; ++i) {
        DPS_PRINT(" %7d ", trueTrace[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("False propagations:   ");
    for (i = 0; i <= treeDepth; ++i) {
        DPS_PRINT(" %7d ", falseTrace[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("Reject by needs check:");
    for (i = 0; i <= treeDepth; ++i) {
        DPS_PRINT(" %7d ", rejectByNeeds[i]);
    }
    DPS_PRINT("\n");

    DPS_PRINT("Reject by pop count:  ");
    for (i = 0; i <= treeDepth; ++i) {
        DPS_PRINT(" %7d ", rejectByPop[i]);
    }
    DPS_PRINT("\n");
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
    int treeDepth = 4;
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
        if (IntArg("-t", &arg, &argc, &treeDepth, 1, MAX_TREE_DEPTH)) {
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
    DPS_PRINT("\n\n");

#ifdef DPS_MQTT_LIKE
    DPS_PRINT("Bit length=%d (%d bytes) MQTT pattern matching\n", bitLen, bitLen / 8);
#else
    DPS_PRINT("Bit length=%d (%d bytes)\n", bitLen, bitLen / 8);
#endif


    RunSimulation(runs, treeDepth, pubs);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-i] [-v] [-t <tree depth>] [b <bits> | -k <kbits>] [-r <runs>] [-d]\n", *argv);
    DPS_PRINT("      -i   Enable infix wildcards\n");
    DPS_PRINT("      -v   Verbose\n");
    DPS_PRINT("      -d   Debugging\n");
    return 1;
}
