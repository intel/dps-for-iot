
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitvec.h>
#include <dps_dbg.h>
#include <topics.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static DPS_BitVector* subUnion;
static DPS_BitVector* pub;
static DPS_BitVector* tmp;

static void FreeTopics(char** topicList, size_t numTopics)
{
    while (numTopics--) {
        free(topicList[numTopics]);
    }
}

static size_t SplitTopics(const char* topics, char** topicList, size_t maxTopics)
{
    size_t num = 0;
    while (num < maxTopics) {
        size_t len = strcspn(topics, " ");
        if (len) {
            topicList[num++] = strndup(topics, len);
        } else {
            topicList[num++] = strdup(topics);
        }
        if (!topics[len]) {
            break;
        }
        topics += len + 1;
    }
    return num;
}

static char* SubTopics[] = {
     "1.1 1.2",
     "2.1.* 2.2.* 2.3.*",
     "1.1",
     "3.0.0.0 3.1.0.0 3.1.0.1",
     "4.*",
     "*.5",
     "i.j.k.l",
     "3.1.*",
     "a.b.c.d",
     "11.22.33.44",
     "11/22/33/44",
     "hello world",
     "hello/world",
};

static int ExpectMatch(size_t numSubscriptions, char** pubs, size_t numPubs)
{
    size_t i;
    int expect = DPS_FALSE;

    for (i = 0; i < numSubscriptions; ++i) {
        char* subs[16];
        size_t num = SplitTopics(SubTopics[i], subs, 16);
        DPS_MatchTopicList(pubs, numPubs, subs, num, "/.", &expect);
        FreeTopics(subs, num);
        if (expect) {
            break;
        }
    }
    //DPS_PRINT("ExpectMatch %s\n", expect ? "TRUE" : "FALSE");
    return expect;
}

static void CandidateCheck(DPS_BitVector* sub, size_t numSubs, DPS_BitVector* pubMask, const char* topicsStr)
{
    char* topics[32];
    size_t i;
    size_t numPubs;
    DPS_BitVector* pm;
    int expect;

    numPubs = SplitTopics(topicsStr, topics, 32);

    DPS_BitVectorClear(pub);
    for (i = 0; i < numPubs; ++i) {
        DPS_AddTopic(pub, topics[i], "/.", DPS_Pub);
    }
    expect = ExpectMatch(numSubs, topics, numPubs);
    FreeTopics(topics, numPubs);

    DPS_BitVectorIntersection(tmp, pub, sub);
    pm = DPS_BitVectorWhiten(tmp);
    if (DPS_BitVectorIsClear(pm)) {
        if (expect) {
            DPS_PRINT("Pub { %s } FALSE rejection based on filter match\n", topicsStr);
        } else {
            DPS_PRINT("Pub { %s } rejected based on filter match\n", topicsStr);
        }
    } else if (!DPS_BitVectorIncludes(pm, pubMask)) {
        if (expect) {
            DPS_PRINT("Pub { %s } FALSE rejection based on publication mask\n", topicsStr);
        } else {
            DPS_PRINT("Pub { %s } rejected based on publication mask\n", topicsStr);
        }
    } else {
        if (expect) {
            DPS_PRINT("Pub { %s } is a candidate\n", topicsStr);
        } else {
            DPS_PRINT("Pub { %s } is a FALSE candidate\n", topicsStr);
        }
    }
    DPS_BitVectorFree(pm);
}

/*
 * A published topic has the form "A<sep>B<sep>C" where <sep> is any of a specified set of separators and
 * A, B, C are arbitrary strings or a standalone wild-card character "*"
 */
static void AddSubTopic(DPS_BitVector* bf, const char* topicsStr)
{
    size_t i;
    char* topics[16];
    size_t num;

    DPS_PRINT("AddSubTopic { %s }\n", topicsStr);
    num = SplitTopics(topicsStr, topics, 16);
    for (i = 0; i < num; ++i) {
        DPS_AddTopic(bf, topics[i], "/.", DPS_Sub);
    }
    FreeTopics(topics, num);
}

static void PubChecks(DPS_BitVector* pubMask, size_t numSubs)
{
    DPS_BitVectorDump(pubMask, 1);
    CandidateCheck(subUnion, numSubs, pubMask, "1.3");
    CandidateCheck(subUnion, numSubs, pubMask, "2.1.1 2.2.1 2.3.1");
    CandidateCheck(subUnion, numSubs, pubMask, "1.1");
    CandidateCheck(subUnion, numSubs, pubMask, "3.1.0.0 3.2.0.0 3.1.0.1");
    CandidateCheck(subUnion, numSubs, pubMask, "3.1.0.0 3.0.0.0 3.1.0.1");
    CandidateCheck(subUnion, numSubs, pubMask, "a b c d e f g h i j k l m n o p q r s t u v w x y z");
    CandidateCheck(subUnion, numSubs, pubMask, "4.1.2.3.4.5.6.7.8.9");
    CandidateCheck(subUnion, numSubs, pubMask, "4.2");
    CandidateCheck(subUnion, numSubs, pubMask, "1.2.3.4.5");
    CandidateCheck(subUnion, numSubs, pubMask, "a.b.c.d.5");
    CandidateCheck(subUnion, numSubs, pubMask, "a.b.c.d.6");
    CandidateCheck(subUnion, numSubs, pubMask, "a.b.c.d");
}

#define _MIN(x, y)  ((x) < (y) ? (x) : (y))

int main(int argc, char** argv)
{
    DPS_Status ret;
    size_t i;
    DPS_BitVector* sub;
    char** arg = argv + 1;
    size_t filterBits = 1024;
    size_t numHashes = 4;
    size_t reduction = 8;
    size_t density = 10;
    DPS_BitVector* pubMask;

    while (--argc) {
        char* p;
        if (strcmp(*arg, "-b") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            filterBits = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-s") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            density = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-r") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            reduction = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-n") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            numHashes = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        goto Usage;
    }

    ret = DPS_Configure(filterBits, numHashes, reduction, density);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    subUnion = DPS_BitVectorAlloc();
    pub = DPS_BitVectorAlloc();
    tmp = DPS_BitVectorAlloc();
    sub = DPS_BitVectorAlloc();

    pubMask = DPS_BitVectorWhiten(NULL);
    DPS_BitVectorFill(pubMask);
    DPS_BitVectorDump(pubMask, 0);

    for (i = 0; i < (sizeof(SubTopics) / sizeof(SubTopics[0])); ++i) {
        DPS_BitVector *pm;
        DPS_BitVectorClear(sub);
        AddSubTopic(sub, SubTopics[i]);
        pm = DPS_BitVectorWhiten(sub);
        DPS_BitVectorUnion(subUnion, sub);
        DPS_BitVectorIntersection(pubMask, pubMask, pm);
        DPS_BitVectorFree(pm);
        PubChecks(pubMask, i + 1);
    }
    DPS_BitVectorDump(subUnion, 0);
    return 0;

Usage:
    DPS_PRINT("Usage %s: [-d] [-b <filter-bits>] [-n <num-hashes>] [-r <reduction>] [-s <density]\n", argv[0]);
    return 1;

}
