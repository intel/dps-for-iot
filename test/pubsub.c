
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitvec.h>
#include <dps_dbg.h>
#include <topics.h>

/*
 * A published topic has the form "A<sep>B<sep>C" where <sep> is any of a specified set of separators and
 * A, B, C are arbitrary strings or a standalone wild-card character "*"
 */
static void AddTopic(DPS_BitVector* filter, const char* topic)
{
    printf("AddTopic %s\n", topic);
    DPS_AddTopic(filter, topic, "/.", DPS_Pub);
    //DPS_BitVectorDump(filter, DPS_TRUE);
}

#define NOT_EXPECT            0
#define EXPECT                1
#define EXPECT_FALSE_POSITIVE 2

static void SubscriptionCheck(DPS_BitVector* pubFilter, const char* subscription, int expect)
{
    if (DPS_MatchTopic(pubFilter, subscription, "/.")) {
        if (expect == EXPECT) {
            printf("Matched expected topic %s: PASS\n", subscription);
        } else if (expect == EXPECT_FALSE_POSITIVE) {
            printf("Matched expected (false positive) topic %s: PASS\n", subscription);
        } else {
            printf("Matched unexpected topic %s: FAIL\n", subscription);
        }
    } else {
        if (expect == EXPECT) {
            printf("No match for expected topic %s: FAIL\n", subscription);
        } else if (expect == EXPECT_FALSE_POSITIVE) {
            printf("No match for expected (false positive) topic %s: FAIL\n", subscription);
        } else {
            printf("No match for topic %s: PASS\n", subscription);
        }
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = argv + 1;
    DPS_BitVector* pubFilter;
    size_t filterBits = 1024;
    size_t numHashes = 4;

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

    ret = DPS_Configure(filterBits, numHashes, 1, 15);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    pubFilter = DPS_BitVectorAlloc();

    AddTopic(pubFilter, "red");
    AddTopic(pubFilter, "blue");
    AddTopic(pubFilter, "foo");
    AddTopic(pubFilter, "foo/bar");
    AddTopic(pubFilter, "foo/baz");
    AddTopic(pubFilter, "foo/baz/gorn");
    AddTopic(pubFilter, "foo/baz/gorn.x");
    AddTopic(pubFilter, "foo/baz/gorn.y");
    AddTopic(pubFilter, "foo/baz/gorn.z");
    AddTopic(pubFilter, "goo/bar");
    AddTopic(pubFilter, "goo/bonzo/gronk");
    AddTopic(pubFilter, "1.0");
    AddTopic(pubFilter, "1.1");
    AddTopic(pubFilter, "1.2");
    AddTopic(pubFilter, "2.0");
    AddTopic(pubFilter, "a.b.c.1");
    AddTopic(pubFilter, "a.b.c.2");
    AddTopic(pubFilter, "a.b.c.3");
    AddTopic(pubFilter, "x.y.c.4");
    AddTopic(pubFilter, "x/y/z");
    AddTopic(pubFilter, "a/b/z");


    //DPS_BitVectorDump(pubFilter, 1);

    SubscriptionCheck(pubFilter, "*/baz", EXPECT);
    SubscriptionCheck(pubFilter, "*/gorn", EXPECT);
    SubscriptionCheck(pubFilter, "*/baz/gorn", EXPECT);
    SubscriptionCheck(pubFilter, "*/gorn.x", EXPECT);
    SubscriptionCheck(pubFilter, "red", EXPECT);
    SubscriptionCheck(pubFilter, "foo", EXPECT);
    SubscriptionCheck(pubFilter, "foo/bar", EXPECT);
    SubscriptionCheck(pubFilter, "foo/bar/*", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "*.z", EXPECT);
    SubscriptionCheck(pubFilter, "*", EXPECT);
    SubscriptionCheck(pubFilter, "*/gorn.blah", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "goo/baz", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "foo/*/gorn", EXPECT);
    SubscriptionCheck(pubFilter, "foo/*.x", EXPECT);
    SubscriptionCheck(pubFilter, "goo/*/gorn", EXPECT_FALSE_POSITIVE);
    SubscriptionCheck(pubFilter, "goo/*.x", EXPECT_FALSE_POSITIVE);
    SubscriptionCheck(pubFilter, "1.*", EXPECT);
    SubscriptionCheck(pubFilter, "2.*", EXPECT);
    SubscriptionCheck(pubFilter, "*.0", EXPECT);
    SubscriptionCheck(pubFilter, "*.1", EXPECT);
    SubscriptionCheck(pubFilter, "*.2", EXPECT);
    SubscriptionCheck(pubFilter, "2.1", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "2.2", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "x.y.c.1", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "a.b.c.4", NOT_EXPECT);
    SubscriptionCheck(pubFilter, "x/b/*", !EXPECT);
    SubscriptionCheck(pubFilter, "*.c.5", !EXPECT);

    return 0;

Usage:
    DPS_PRINT("Usage %s: [-r] [-b <filter-bits>] [-n <num-hashes>]\n", argv[0]);
    return 1;
}
