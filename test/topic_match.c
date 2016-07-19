
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps_dbg.h>
#include <topics.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

extern int TopicStrategy;

#define MAX_TOPICS  32

int main(int argc, char** argv)
{
    char* pubs[MAX_TOPICS + 1];
    char* subs[MAX_TOPICS + 1];
    char** topics = NULL;
    size_t numPubs = 0;
    size_t numSubs = 0;
    DPS_Status ret;
    char* *arg = argv + 1;
    int match;

    while (--argc) {
        if (numPubs == MAX_TOPICS || numSubs == MAX_TOPICS) {
            goto Usage;
        }
        if (strcmp(*arg, "-2") == 0) {
            ++arg;
            TopicStrategy = 2;
            continue;
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
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            topics = NULL;
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
    if (!numPubs || !numPubs) {
        goto Usage;
    }
    ret = DPS_MatchTopicList(pubs, numPubs, subs, numSubs, "/.", &match);
    if (ret != DPS_OK) {
        DPS_PRINT("Error: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    if (match) {
        DPS_PRINT("Match\n");
    } else {
        DPS_PRINT("No match\n");
    }
    return 0;

Usage:
    DPS_PRINT("Usage %s: [-d] -p <pub topics> -s <sub topics>\n", argv[0]);
    return 1;

}
