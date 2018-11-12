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

#include "test.h"
#include <dps/private/bitvec.h>
#include <dps/private/topics.h>

/*
 * A published topic has the form "A<sep>B<sep>C" where <sep> is any of a specified set of separators and
 * A, B, C are arbitrary strings or a standalone wild-card character "*"
 */
static DPS_Status AddTopic(DPS_BitVector* bv, const char* topic)
{
    DPS_Status status;
    DPS_PRINT("AddTopic %s\n", topic);
    status = DPS_AddTopic(bv, topic, "/.", DPS_PubTopic);
    if (status == DPS_OK) {
        if (DPS_Debug) {
            DPS_BitVectorDump(bv);
        }
    }
    return status;
}

#define NOT_EXPECT            0
#define EXPECT                1
#define EXPECT_FALSE_POSITIVE 2

static void SubscriptionCheck(DPS_BitVector* bv, const char* subscription, int expect)
{
    if (DPS_MatchTopic(bv, subscription, "/.")) {
        if (expect == EXPECT) {
            DPS_PRINT("Matched expected topic %s: PASS\n", subscription);
        } else if (expect == EXPECT_FALSE_POSITIVE) {
            DPS_PRINT("Matched expected (false positive) topic %s: PASS\n", subscription);
        } else {
            DPS_PRINT("Matched unexpected topic %s: FAIL\n", subscription);
            exit(1);
        }
    } else {
        if (expect == EXPECT) {
            DPS_PRINT("No match for expected topic %s: FAIL\n", subscription);
            exit(1);
        } else if (expect == EXPECT_FALSE_POSITIVE) {
            DPS_PRINT("No match for expected (false positive) topic %s: FAIL\n", subscription);
        } else {
            DPS_PRINT("No match for topic %s: PASS\n", subscription);
        }
    }
}

int main(int argc, char** argv)
{
    DPS_Status status;
    char** arg = argv + 1;
    DPS_BitVector bv;


    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        goto Usage;
    }

    DPS_BitVectorClear(&bv);
    status = AddTopic(&bv, "1");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "x/y");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "red");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "blue");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/bar");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/baz");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/baz/gorn");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/baz/gorn.x");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/baz/gorn.y");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "foo/baz/gorn.z");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "goo/bar");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "goo/bonzo/gronk");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "1.0");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "1.1");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "1.2");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "2.0");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "a.b.c.1");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "a.b.c.2");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "a.b.c.3");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "x.y.c.4");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "x/y/z");
    CHECK(status == DPS_OK);
    status = AddTopic(&bv, "a/b/z");
    CHECK(status == DPS_OK);

    DPS_BitVectorDump(&bv);

    SubscriptionCheck(&bv, "+", EXPECT);
    SubscriptionCheck(&bv, "#", EXPECT);
    SubscriptionCheck(&bv, "+/+", EXPECT);
    SubscriptionCheck(&bv, "foo/+/+.#", EXPECT);
    SubscriptionCheck(&bv, "foo/+/+/+/#", NOT_EXPECT);
    SubscriptionCheck(&bv, "+/baz", EXPECT);
    SubscriptionCheck(&bv, "+/+/gorn", EXPECT);
    SubscriptionCheck(&bv, "+/baz/gorn", EXPECT);
    SubscriptionCheck(&bv, "+/+/gorn.x", EXPECT);
    SubscriptionCheck(&bv, "red", EXPECT);
    SubscriptionCheck(&bv, "foo", EXPECT);
    SubscriptionCheck(&bv, "foo/bar", EXPECT);
    SubscriptionCheck(&bv, "foo/bar/*", NOT_EXPECT);
    SubscriptionCheck(&bv, "+/+/+.z", EXPECT);
    SubscriptionCheck(&bv, "foo/#", EXPECT);
    SubscriptionCheck(&bv, "+/gorn.blah", NOT_EXPECT);
    SubscriptionCheck(&bv, "goo/baz", NOT_EXPECT);
    SubscriptionCheck(&bv, "foo/+/gorn", EXPECT);
    SubscriptionCheck(&bv, "foo/+/+.x", EXPECT);
    SubscriptionCheck(&bv, "foo/baz/gorn.z/1", NOT_EXPECT);
    SubscriptionCheck(&bv, "goo/baz/gorn.z", NOT_EXPECT);
    SubscriptionCheck(&bv, "goo/+/gorn", EXPECT_FALSE_POSITIVE);
    SubscriptionCheck(&bv, "goo/+/+.x", EXPECT_FALSE_POSITIVE);
    SubscriptionCheck(&bv, "1.#", EXPECT);
    SubscriptionCheck(&bv, "2.#", EXPECT);
    SubscriptionCheck(&bv, "+.0", EXPECT);
    SubscriptionCheck(&bv, "+.1", EXPECT);
    SubscriptionCheck(&bv, "+.2", EXPECT);
    SubscriptionCheck(&bv, "2.1", NOT_EXPECT);
    SubscriptionCheck(&bv, "2.2", NOT_EXPECT);
    SubscriptionCheck(&bv, "x.y.c.1", NOT_EXPECT);
    SubscriptionCheck(&bv, "a.b.c.4", NOT_EXPECT);
    SubscriptionCheck(&bv, "x/b/#", NOT_EXPECT);
    SubscriptionCheck(&bv, "+.+.c.5", NOT_EXPECT);
    SubscriptionCheck(&bv, "1", EXPECT);
    SubscriptionCheck(&bv, "2", NOT_EXPECT);

    return 0;

failed:
    printf("FAILED (%s) near line %d\r\n", __FILE__, atLine - 1);
    return 1;

Usage:
    DPS_PRINT("Usage %s: [-r] [-b <filter-bits>] [-n <num-hashes>]\n", argv[0]);
    return 1;
}
