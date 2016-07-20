
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
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#ifdef DPS_MQTT_LIKE
#define FINAL_WILDC    '#'
#define INFIX_WILDC    '+'
#define WILDCARDS     "+#"
#else
#define FINAL_WILDC    '*'
#define INFIX_WILDC    '*'
#define WILDCARDS      "*"
#endif

static DPS_Status CheckWildcarding(const char* topic, const char* separators, DPS_Role role, const char** wcPos)
{
    const char* wc = topic + strcspn(topic, WILDCARDS);

    *wcPos = NULL;
    if (wc[0]) {
        /*
         * Wildcards are only allowed in subscriptions
         */
        if (role != DPS_Sub) {
            return DPS_ERR_INVALID;
        }
        /*
         * Leading wilcards not allowed
         */
        if (wc == topic) {
            return DPS_ERR_INVALID;
        }
        /*
         * Return position of first wildcard
         */
        *wcPos = wc;
        do {
            /*
             * Wildcards must be preceded by a separator
             */
            if (!strchr(separators, wc[-1])) {
                return DPS_ERR_INVALID;
            }
            if (!wc[1]) {
                return wc[0] == FINAL_WILDC ? DPS_OK : DPS_ERR_INVALID;
            }
            if (wc[0] != INFIX_WILDC) {
                return DPS_ERR_INVALID;
            }
            /*
             * Infix  wildcard must be followed by a separator
             */
            if (!strchr(separators, wc[1])) {
                return DPS_ERR_INVALID;
            }
            wc += 2;
            wc += strcspn(wc, WILDCARDS);
        } while (*wc);
    }
    /*
     * Topic cannot end in a separator
     */
    if (strchr(separators, wc[-1])) {
        return DPS_ERR_INVALID;
    }
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
    char* segment;
    size_t prefix = 0;
    const char* tp;
    const char* wc;
    size_t tlen;

    if (!bf || !topic || !separators) {
        return DPS_ERR_NULL;
    }
    tlen = strlen(topic);
    if (strchr(separators, topic[0])) {
        DPS_ERRPRINT("Topic string cannot start with a separator\n");
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(topic, separators, role, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in topic string\n");
        return ret;
    }
    tp = topic + strcspn(topic, separators);
    if (!wc) {
        DPS_BitVectorBloomInsert(bf, topic, tlen);
        if (role == DPS_Sub) {
            return DPS_OK;
        }
    } else {
        DPS_BitVectorBloomInsert(bf, topic, wc - topic);
    }
    segment = malloc(tlen + 1);
    if (!segment) {
        return DPS_ERR_RESOURCES;
    }
    while (*tp) {
        int len;
        segment[prefix++] = *tp++;
        if (role == DPS_Pub) {
            DPS_BitVectorBloomInsert(bf, topic, tp - topic);
        }
        len = strcspn(tp, separators);
        if ((tp > wc) && (*tp != INFIX_WILDC)) {
            memcpy(segment + prefix, tp, len);
            segment[prefix + len] = tp[len];
            DPS_BitVectorBloomInsert(bf, segment, prefix + len + 1);
        }
        tp += len;
    }
#ifdef DPS_MQTT_LIKE
    if (role == DPS_Pub) {
        segment[prefix++] = FINAL_WILDC;
        DPS_BitVectorBloomInsert(bf, segment, prefix);
    }
#endif
    free(segment);
    return DPS_OK;
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
    const char* wc;

    if (!pubTopic || !subTopic || !separators || !match) {
        return DPS_ERR_NULL;
    }
    if (*pubTopic == 0 || *subTopic == 0 || *separators == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(pubTopic, separators, DPS_Pub, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in PUB topic string\n");
        return ret;
    }
    ret = CheckWildcarding(subTopic, separators, DPS_Sub, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in SUB topic string\n");
        return ret;
    }
    *match = DPS_TRUE;
    while (*pubTopic && *subTopic) {
        if ((subTopic[0] == INFIX_WILDC) || (subTopic[0] == FINAL_WILDC)) {
            int len = strcspn(pubTopic, separators);
            if (len) {
                pubTopic += len;
                if (subTopic[0] == FINAL_WILDC && subTopic[1] == 0) {
                    return DPS_OK;
                }
            }
            ++subTopic;
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
