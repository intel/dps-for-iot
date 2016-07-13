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

#define MAX_PUB_TOPICS     2
#define NUM_PUB_FORMATS    5

static const char* pubFormats[NUM_PUB_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/%d/%d"
};

#define MAX_SUB_TOPICS        4  /* Max topics per subscription */
#define NUM_SUB_FORMATS       9
#define FIRST_INFIX_WILDCARD  7  /* First format string with infix wild card */

static const char* subFormats[NUM_SUB_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/*",
    "%d/*",
    "*/%d",
    /* infix wildcards last so can be optionally excluded */
    "%d/*/%d/%d",
    "%d/*/%d"
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

static size_t InitSub(DPS_BitVector* bv, char* topics[])
{
    DPS_Status ret;
    size_t i = 0;
    size_t numSubs = 1 + (rand() % (MAX_SUB_TOPICS - 1));

    DPS_BitVectorClear(bv);

    while (i < numSubs) {
        int fmt = rand() % NUM_SUB_FORMATS;
        if (fmt < FIRST_INFIX_WILDCARD || infixWildcards) {
            int a = rand() % 4;
            int b = rand() % 4;
            int c = rand() % 4;
            int d = rand() % 4;
            topics[i] = malloc(32);
            sprintf(topics[i], subFormats[fmt], a, b, c, d);
            ret = DPS_AddTopic(bv, topics[i], "/.", DPS_Sub);
            assert(ret == DPS_OK);
            ++i;
        }
    }
    return numSubs;
}

static size_t InitPub(DPS_BitVector* bv, char* topics[])
{
    DPS_Status ret;
    size_t i;
    size_t numPubs = 1 + (rand() % (MAX_PUB_TOPICS - 1));

    DPS_BitVectorClear(bv);

    for (i = 0; i < numPubs; ++i) {
        /*
         * Build a random topic
         */
        int fmt = rand() % NUM_PUB_FORMATS;
        int a = rand() % 4;
        int b = rand() % 4;
        int c = rand() % 4;
        int d = rand() % 4;
        int e = rand() % 4;
        topics[i] = malloc(32);
        sprintf(topics[i], pubFormats[fmt], a, b, c, d, e);
        ret = DPS_AddTopic(bv, topics[i], "/.", DPS_Pub);
        assert(ret == DPS_OK);
    }
    return numPubs;
}

#define MAX_LEAFS 5

typedef struct _SubTopic {
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    char* strings[MAX_SUB_TOPICS];
    size_t count;
    int expect;
    int wastedPubs;
    int falseMatches;
    int trueMatches;
    int totalSubs;
    size_t numLeafs;
    struct _SubTopic* leaf[1];
} SubTopic;

static SubTopic* BuildTree(int depth)
{
    size_t i;
    SubTopic* topic;

    if (depth > 0) {
        int numLeafs = 1 + rand() % MAX_LEAFS;
        topic = calloc(1, sizeof(SubTopic) + sizeof(struct _SubTopic*) * (numLeafs - 1));
        for (i = 0; i < numLeafs; ++i) {
            topic->leaf[i] = BuildTree(depth - 1);
        }
        topic->numLeafs = numLeafs;
    } else {
        topic = calloc(1, sizeof(SubTopic));
    }
    topic->interests = DPS_BitVectorAlloc();
    return topic;
}

static void FreeTree(SubTopic* topic)
{
    size_t i;
    for (i = 0; i < topic->numLeafs; ++i) {
        FreeTree(topic->leaf[i]);
    }
    DPS_BitVectorFree(topic->interests);
    free(topic);
}

static void ShowTree(SubTopic* topic, int depth)
{
    char in[64];

    memset(in, topic->expect ? '+' : '-', depth * 2);
    in[depth * 2] = 0;
    if (topic->numLeafs > 0) {
        size_t i;
        DPS_PRINT("%s%d\n", in, topic->numLeafs);
        for (i = 0; i < topic->numLeafs; ++i) {
            ShowTree(topic->leaf[i], depth + 1);
        }
    } else {
        PrintTopics(in, topic->strings, topic->count);
    }
}

static void CleanTree(SubTopic* topic)
{
    size_t i;
    for (i = 0; i < topic->numLeafs; ++i) {
        CleanTree(topic->leaf[i]);
    }
    DPS_BitVectorFree(topic->needs);
    FreeTopics(topic->strings, topic->count);
}

static void PopulateTree(SubTopic* topic)
{
    if (topic->numLeafs == 0) {
        topic->count = InitSub(topic->interests, topic->strings);
        topic->needs = DPS_BitVectorWhiten(topic->interests);
        topic->totalSubs += topic->count;
    } else {
        size_t i;
        DPS_BitVectorClear(topic->interests);
        topic->needs = DPS_BitVectorWhiten(NULL);
        for (i = 0; i < topic->numLeafs; ++i) {
            PopulateTree(topic->leaf[i]);
            DPS_BitVectorUnion(topic->interests, topic->leaf[i]->interests);
            DPS_BitVectorIntersection(topic->needs, topic->needs, topic->leaf[i]->needs);
        }
    }
}

static int SetExpects(SubTopic* topic, char** pubs, size_t numPubs)
{
    if (topic->numLeafs == 0) {
        DPS_MatchTopicList(pubs, numPubs, topic->strings, topic->count, "/.", &topic->expect);
    } else {
        size_t i;
        topic->expect = 0;
        for (i = 0; i < topic->numLeafs; ++i) {
            topic->expect |= SetExpects(topic->leaf[i], pubs, numPubs);
        }
    }
    return topic->expect;
}

static void PropogatePub(SubTopic* topic, DPS_BitVector* pub)
{
    DPS_Status ret;
    int match;

    //DPS_PRINT("Pub: "); DPS_BitVectorDump(pub, 0);
    if (topic->numLeafs == 0) {
        match = DPS_BitVectorIncludes(pub, topic->interests);
        if (match) {
            if (topic->expect) {
                ++topic->trueMatches;
            } else {
                ++topic->falseMatches;
            }
        } else {
            if (topic->expect) {
                DPS_PRINT("False negative at leaf\n");
            }
        }
    } else {
        DPS_BitVector* provides;
        DPS_BitVector* tmp = DPS_BitVectorAlloc();
        size_t i;
        for (i = 0; i < topic->numLeafs; ++i) {
            SubTopic* leaf = topic->leaf[i];
            DPS_BitVector* provides;
            /*
             * Duplicates match logic from dps.c
             */
            ret = DPS_BitVectorIntersection(tmp, pub, leaf->interests);
            assert(ret == DPS_OK);
            provides = DPS_BitVectorWhiten(tmp);
            match = DPS_BitVectorIncludes(provides, leaf->needs);
            if (match) {
                if (!leaf->expect) {
                    /*
                     * Count number of wasted pub forwards from this node
                     */
                    ++topic->wastedPubs;
                }
                PropogatePub(leaf, tmp);
            } else {
                if (leaf->expect) {
                    DPS_PRINT("False negative\n");
                }
            }
            DPS_BitVectorFree(provides);
        }
        DPS_BitVectorFree(tmp);
    }
}

typedef struct {
    int trueMatches;
    int falseMatches;
    int wastedPubs;
    int totalSubs;
    int nodes;
} Stats;

static void Analyze(SubTopic* topic, Stats* stats)
{
    size_t i;

    ++stats->nodes;
    stats->trueMatches += topic->trueMatches;
    stats->falseMatches += topic->falseMatches;
    stats->wastedPubs += topic->wastedPubs;
    stats->totalSubs += topic->totalSubs;
    for (i = 0; i < topic->numLeafs; ++i) {
        Analyze(topic->leaf[i], stats);
    }
}

static void RunSimulation(int runs, int numSubs, int pubIters)
{
    DPS_Status ret;
    int r;
    DPS_BitVector* pub = DPS_BitVectorAlloc();
    SubTopic* subscriptions;
    int pubs = 0;
    Stats stats;
    float maxLoad = 0.0;
    float totalLoad = 0.0;

    subscriptions = BuildTree(numSubs);

    PopulateTree(subscriptions);

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
        //DPS_PRINT("Sub: "); DPS_BitVectorDump(subscriptions->interests, 0);
        /*
         * Tests random publications against the subscriptions
         */
        for (p = 0; p < pubIters; ++p) {
            char* pubTopics[MAX_PUB_TOPICS];
            size_t numPubTopics = InitPub(pub, pubTopics);
            /*
             * Identify expected matches
             */
            SetExpects(subscriptions, pubTopics, numPubTopics);
            /*
             * Propogate the publication up the tree
             */
            PropogatePub(subscriptions, pub);
            FreeTopics(pubTopics, numPubTopics);
            ++pubs;
        }
        /*
         * Done with these subscriptions
         */
        CleanTree(subscriptions);
    }
    DPS_BitVectorFree(pub);

    memset(&stats, 0, sizeof(stats));
    Analyze(subscriptions, &stats);
    DPS_PRINT("Nodes=%d, pubs=%d\n", stats.nodes, pubs);
    DPS_PRINT("Max load=%2.3f%%, Avg load=%2.3f%%\n", maxLoad, totalLoad / runs);
    DPS_PRINT("Subs=%d, Matches=%d, false matches=%d, wasted pubs=%d\n",
            stats.totalSubs, stats.trueMatches, stats.falseMatches, stats.wastedPubs);
    DPS_PRINT("Waste ratio=%2.2f%%\n", (float)(stats.wastedPubs * 100) / (float)(pubs * stats.nodes));

    FreeTree(subscriptions);
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
    int bitLen = 1024 * 16;
    int runs = 100;
    int whitening = 10;
    int subLevels = 4;
    int hashes = 4;
    int scaling = 32;
    DPS_Status ret;
    char** arg = ++argv;

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
        if (IntArg("-l", &arg, &argc, &subLevels, 1, 8)) {
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
        if (IntArg("-w", &arg, &argc, &whitening, 1, 60)) {
            continue;
        }
        goto Usage;
    }

    if (DPS_Configure(bitLen, hashes, scaling, whitening) != DPS_OK) {
        DPS_PRINT("Invalid configuration parameters\n");
        return 1;
    }
    DPS_PRINT("Bit length=%d (%d bytes) whitened length=%d\n", bitLen, bitLen / 8, bitLen / scaling);

    RunSimulation(runs, subLevels, 100);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-i] [-v] [-l <levels>] [b <bits> | -k <kbits>] [-r <runs>] [-d]\n", *argv);
    DPS_PRINT("      -i   Enable infix wildcards\n");
    DPS_PRINT("      -v   Verbose\n");
    DPS_PRINT("      -d   Debugging\n");
    return 1;
}


