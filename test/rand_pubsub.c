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

#define MAX_PUB_TOPICS     4
#define NUM_PUB_FORMATS    5

static const char* pubFormats[NUM_PUB_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/%d/%d"
};

#define MAX_SUB_TOPICS        4  /* Max topics per subscription */
#define NUM_SUB_FORMATS       8
#define FIRST_INFIX_WILDCARD  6  /* First format string with infix wild card */

static const char* subFormats[NUM_SUB_FORMATS] = {
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

typedef struct {
    DPS_BitVector* interests;
    DPS_BitVector* needs;
    char* strings[MAX_SUB_TOPICS];
    size_t count;
    int expect;
    int falsePositives;
} TopicList;


static void RunSimulation(int runs, int numSubs, int pubIters)
{
    DPS_Status ret;
    float sumLoad = 0.0;
    float maxLoad = 0.0;
    int r;
    int s;
    int i;
    int numPubs = 0;
    int numMatches = 0;
    int falseNegatives = 0;
    DPS_BitVector* pub;
    TopicList* topics;

    topics = malloc(numSubs * sizeof(TopicList));
    for (s = 0; s < numSubs; ++s) {
        topics[s].interests = DPS_BitVectorAlloc();
        topics[s].falsePositives = 0;
    }
    pub = DPS_BitVectorAlloc();

    for (r = 0; r < runs; ++r) {
        int p;
        float loadFactor;
        /*
         * Build a cascade of subscriptions.
         */
        for (s = 0; s < numSubs; ++s) {
            topics[s].count = InitSub(topics[s].interests, topics[s].strings);
            topics[s].needs = DPS_BitVectorWhiten(topics[s].interests);
            if (s > 0) {
                DPS_BitVectorIntersection(topics[s].needs, topics[s].needs, topics[s -1].needs);
                DPS_BitVectorUnion(topics[s].interests, topics[s -1].interests);
            }
        }
        /*
         * Gather some statistics about the bit population
         */
        loadFactor = DPS_BitVectorLoadFactor(topics[numSubs - 1].interests);
        if (loadFactor > maxLoad) {
            maxLoad = loadFactor;
        }
        sumLoad += loadFactor;
        /*
         * Tests random publications against the subscriptions
         */
        for (p = 0; p < pubIters; ++p) {
            char* pubTopics[MAX_PUB_TOPICS];
            size_t numPubTopics = InitPub(pub, pubTopics);
            /*
             * Identify expected matches - after a match we expect all the way down the cascade
             */
            for (s = 0; s < numSubs; ++s) {
                if (s > 0 && topics[s - 1].expect) {
                    topics[s].expect = 1;
                } else {
                    DPS_MatchTopicList(pubTopics, numPubTopics, topics[s].strings, topics[s].count, "/.", &topics[s].expect);
                }
            }
            /*
             * Work up the cascade match the publication to the subscriptions simulating how publications get routed up a node tree
             */
            for (s = numSubs - 1; s >= 0; --s) {
                DPS_BitVector* provides;

                ret = DPS_BitVectorIntersection(pub, pub, topics[s].interests);
                assert(ret == DPS_OK);
                provides = DPS_BitVectorWhiten(pub);
                /*
                 * The match check
                 */
                if (!DPS_BitVectorIsClear(provides) && DPS_BitVectorIncludes(provides, topics[s].needs)) {
                    if (topics[s].expect) {
                        ++numMatches;
                    } else {
                        if (verbose) {
                            DPS_PRINT("False positive (level=%d)\n", s);
                            PrintTopics("pub", pubTopics, numPubTopics);
                            for (i = s; i >= 0; --i) {
                                PrintTopics("sub", topics[i].strings, topics[i].count);
                            }
                        }
                        ++topics[s].falsePositives;
                    }
                } else {
                    if (topics[s].expect) {
                        DPS_PRINT("False negative\n");
                        PrintTopics("pub", pubTopics, numPubTopics);
                        for (i = s; i >= 0; --i) {
                            PrintTopics("sub", topics[i].strings, topics[i].count);
                        }
                        DPS_BitVectorDump(topics[s].interests, 1);
                        DPS_BitVectorDump(pub, 1);
                        DPS_BitVectorDump(topics[s].needs, 1);
                        DPS_BitVectorDump(provides, 1);
                        ++falseNegatives;
                    }
                }
                DPS_BitVectorFree(provides);
                ++numPubs;
            }
            FreeTopics(pubTopics, numPubTopics);
        }
        /*
         * Done with these subscriptions
         */
        for (s = 0; s < numSubs; ++s) {
            FreeTopics(topics[s].strings, topics[s].count);
            DPS_BitVectorFree(topics[s].needs);
        }
    }

    DPS_PRINT("Total pubs = %d, matches=%d\n", numPubs, numMatches);
    if (falseNegatives) {
        DPS_PRINT("ERROR!!!! %s false negatives\n");
    }
    DPS_PRINT("False positives %2.2f%%\n", (float)(100 * topics[numSubs - 1].falsePositives) / (float)numPubs);
    for (s = numSubs - 1; s >= 0; --s) {
        DPS_PRINT("%d ", topics[s].falsePositives);
        DPS_BitVectorFree(topics[s].interests);
    }
    DPS_PRINT("\n");

    free(topics);
    DPS_BitVectorFree(pub);

    DPS_PRINT("Average load=%2.2f%%, max load=%2.2f%%\n", sumLoad / runs, maxLoad);
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
    int bitLen = 1024 * 32;
    int runs = 100;
    int whitening = 20;
    int subLevels = 40;
    int hashes = 4;
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
        if (IntArg("-l", &arg, &argc, &subLevels, 1, 200)) {
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

    if (DPS_Configure(bitLen, hashes, bitLen / 64, whitening) != DPS_OK) {
        DPS_PRINT("Invalid configuration parameters\n");
        return 1;
    }
    DPS_PRINT("Bit length=%d (%d bytes) whitened length=%d\n", bitLen, bitLen / 8, bitLen / 128);

    RunSimulation(runs, subLevels, 1000);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-i] [-v] [-l <levels>] [b <bits> | -k <kbits>] [-r <runs>] [-d]\n", *argv);
    DPS_PRINT("      -i   Enable infix wildcards\n");
    DPS_PRINT("      -v   Verbose\n");
    DPS_PRINT("      -d   Debugging\n");
    return 1;
}


