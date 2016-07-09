
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <topics.h>
#include <dps_dbg.h>
#include <bitvec.h>
#include <dps.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);


#define WILDCARD  '*'

static DPS_Status CheckWildcarding(const char* topic, const char* separators, DPS_Role role, char** wcPos)
{
    char* wc = strchr(topic, WILDCARD);

    /*
     * The wildcard cannot appear in the separators list
     */
    if (strchr(separators, WILDCARD)) {
        return DPS_ERR_INVALID;
    }
    if (wc) {
        /*
         * Wildcards are only allowed in subscriptions
         */
        if (role == DPS_Pub) {
            return DPS_ERR_INVALID;
        }
        if (wc[1]) {
            if (wc == topic) {
                /*
                 * Leading wildchard must be followed by a separator
                 */
                if (!strchr(separators, wc[1])) {
                    return DPS_ERR_INVALID;
                }
            } else {
                /*
                 * Infix wildcard must have a separator on each side
                 */
                if (!strchr(separators, wc[1]) || !strchr(separators, wc[-1])) {
                    return DPS_ERR_INVALID;
                }
            }
            /*
             * Only one wild card allowed
             */
            if (strchr(wc + 1, WILDCARD)) {
                return DPS_ERR_INVALID;
            }
        } else {
            /*
             * Trailing wildcard must be preceded by a separator
             */
            if (!strchr(separators, wc[-1])) {
                return DPS_ERR_INVALID;
            }
        }
    }
    *wcPos = wc;
    return DPS_OK;
}

/**
 * A topic has the form "A<sep>B<sep>C" where <sep> is any of a specified set of separators and A, B, C are arbitrary
 * strings or a standalone wild-card character "*". Wildcards are only meaningful in subscriptions and there can only be
 * on wildcard in a topic string.
 *
 * Note that when there are multiple topics in one publication, infix wildcard subscriptions are more prone to false
 * positives.  For example, if a single publication includes two topic strings "a.b.1" and "c.d.2" the subscriptions
 * "a.*.2" or "c.*.1" will return false positive matches.
 *
 * This is because the bits representing prefixes "a.", "c." and the suffixes ".2", ".1" are both present in the publication 
 * Bloom filter. 
 */
DPS_Status DPS_AddTopic(DPS_BitVector* bf, const char* topic, const char* separators, DPS_Role role)
{
    DPS_Status ret = DPS_OK;
    size_t tLen;
    char* wc;

    if (!bf || !topic || !separators) {
        return DPS_ERR_NULL;
    }
    tLen = strlen(topic);
    if (tLen == 0 || *separators == 0) {
        return DPS_ERR_INVALID;
    }
    if (strchr(separators, topic[0])) {
        DPS_ERRPRINT("Topic string cannot start with a separator\n");
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(topic, separators, role, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wilcard in %s topic string\n", role == DPS_Pub ? "PUB" : "SUB");
        return ret;
    }
    if (role == DPS_Sub) {
        if (!wc) {
            DPS_BitVectorBloomInsert(bf, topic, tLen);
        } else {
            if (wc[1]) {
                DPS_BitVectorBloomInsert(bf, wc + 1, tLen - (wc -topic) - 1);
            }
            if (wc != topic) {
                DPS_BitVectorBloomInsert(bf, topic, wc - topic);
            }
        }
    } else {
        const char* tp = topic;
        DPS_BitVectorBloomInsert(bf, topic, tLen);
        while (1) {
            int len = strcspn(tp, separators);
            tp += len;
            if (!*tp) {
                break;
            }
            DPS_BitVectorBloomInsert(bf, tp, tLen - (tp - topic));
            ++tp;
            DPS_BitVectorBloomInsert(bf, topic, tp - topic);
        }

    }
    return ret;
}

int DPS_MatchTopic(DPS_BitVector* bf, const char* topic, const char* separators)
{
    int match = DPS_FALSE;
    DPS_BitVector* tmp = DPS_BitVectorAlloc();

    if (tmp) {
        if (DPS_AddTopic(tmp, topic, separators, DPS_Sub) == DPS_OK) {
            match = DPS_BitVectorIncludes(bf, tmp);
        }
        DPS_BitVectorFree(tmp);
    }
    return match;
}

DPS_Status DPS_MatchTopicString(const char* pubTopic, const char* subTopic, const char* separators, int* match)
{
    DPS_Status ret;
    char* wc;
    
    if (!pubTopic || !subTopic || !separators || !match) {
        return DPS_ERR_NULL;
    }
    if (*pubTopic == 0 || *subTopic == 0 || *separators == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(pubTopic, separators, DPS_Pub, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wilcard in PUB topic string\n");
        return ret;
    }
    ret = CheckWildcarding(subTopic, separators, DPS_Sub, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wilcard in SUB topic string\n");
        return ret;
    }
    *match = DPS_TRUE;
    while (*pubTopic && *subTopic) {
        if (*subTopic == '*') {
            int len = strcspn(pubTopic, separators);
            if (len) {
                pubTopic += len;
                if (strcmp(pubTopic, subTopic + 1) == 0) {
                    return DPS_OK;
                }
            } else {
                ++subTopic;
            }
            if (*pubTopic) {
                ++pubTopic;
            }
            continue;
        }
        if (*pubTopic++ != *subTopic++) {
            *match = DPS_FALSE;
            break;
        }
    }
    if (*subTopic || *pubTopic) {
        *match = DPS_FALSE;
    }
    return DPS_OK;
}

DPS_Status DPS_MatchTopicList(char* const* pubs, size_t numPubs, char* const* subs, size_t numSubs, const char* separators, int* match)
{
    DPS_Status ret;

    if (!pubs || !subs || !separators || !match) {
        return DPS_ERR_NULL;
    }
    *match = DPS_TRUE;
    while (numSubs--) {
        int ok = DPS_FALSE;
        size_t i;
        for (i = 0; i < numPubs; ++i) {
            ret = DPS_MatchTopicString(pubs[i], *subs, separators, &ok);
            if (ret != DPS_OK) {
                return ret;
            }
            if (ok) {
                break;
            }
        }
        if (!ok) {
            *match = DPS_FALSE;
            break;
        }
        ++subs;
    }
    return ret;
}
