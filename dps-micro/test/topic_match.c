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
#include <dps/dbg.h>
#include <dps/private/topics.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define MAX_TOPICS  32

const char separators[] = "/";

static int BloomMatch(const char** pubs, size_t numPubs, const char** subs, size_t numSubs, int noWildCard)
{
    int cmp;
    DPS_BitVector pubBf;
    DPS_BitVector subBf;
    
    DPS_BitVectorClear(&pubBf);
    DPS_BitVectorClear(&subBf);

    DPS_PRINT("Pubs\n");
    while (numPubs--) {
        DPS_AddTopic(&pubBf, *pubs++, separators, noWildCard ? DPS_PubNoWild : DPS_PubTopic);
    }
    DPS_PRINT("Subs\n");
    while (numSubs--) {
        DPS_AddTopic(&subBf, *subs++, separators, DPS_SubTopic);
    }
    cmp = DPS_BitVectorIncludes(&pubBf, &subBf);

    return cmp;
}

int main(int argc, char** argv)
{
    const char* pubs[MAX_TOPICS + 1];
    const char* subs[MAX_TOPICS + 1];
    const char** topics = NULL;
    size_t numPubs = 0;
    size_t numSubs = 0;
    DPS_Status ret;
    char* *arg = argv + 1;
    int match;
    int noWildCard = DPS_FALSE;

    while (--argc) {
        if (numPubs == MAX_TOPICS || numSubs == MAX_TOPICS) {
            goto Usage;
        }
        if (*arg[0] == '-') {
            topics = NULL;
        }
        if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            pubs[numPubs++] = *arg++;
            topics = pubs;
            continue;
        }
        if (strcmp(*arg, "-s") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            subs[numSubs++] = *arg++;
            topics = subs;
            continue;
        }
        if (strcmp(*arg, "-n") == 0) {
            ++arg;
            noWildCard = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (topics == subs) {
            subs[numSubs++] = *arg++;
            continue;
        }
        if (topics == pubs) {
            pubs[numPubs++] = *arg++;
            continue;
        }
        goto Usage;
    }
    if (!numPubs || !numSubs) {
        goto Usage;
    }
    ret = DPS_MatchTopicList(pubs, numPubs, subs, numSubs, separators, noWildCard, &match);
    if (ret != DPS_OK) {
        DPS_PRINT("Error: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    if (match) {
        DPS_PRINT("Match\n");
    } else {
        DPS_PRINT("No match\n");
    }
    if (BloomMatch(pubs, numPubs, subs, numSubs, noWildCard) != match) {
        DPS_PRINT("FAILURE: Different bloom filter match\n");
    }
    return 0;

Usage:
    DPS_PRINT("Usage %s: [-d] -p <pub topics> -s <sub topics>\n", argv[0]);
    return 1;
}
