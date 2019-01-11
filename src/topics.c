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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/targets.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/topics.h>
#include <dps/private/bitvec.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define FINAL_WILDC    '#'
#define INFIX_WILDC    '+'
#define WILDCARDS     "+#"

#define ANY_WILDC(c)  ((c) == FINAL_WILDC || (c) == INFIX_WILDC)

static DPS_Status CheckWildcarding(const char* topic, const char* separators, DPS_TopicType topicType, const char** wcPos)
{
    const char* wc = topic + strcspn(topic, WILDCARDS);

    *wcPos = NULL;
    if (wc[0]) {
        /*
         * Wildcards are only allowed in subscriptions
         */
        if (topicType != DPS_SubTopic) {
            return DPS_ERR_INVALID;
        }
        /*
         * A topic cannot start with a final wildcard
         */
        if (wc == topic && wc[0] == FINAL_WILDC && wc[1] != 0) {
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
            if (wc != topic && !strchr(separators, wc[-1])) {
                return DPS_ERR_INVALID;
            }
            if (!wc[1]) {
                return ANY_WILDC(wc[0]) ? DPS_OK : DPS_ERR_INVALID;
            }
            if (wc[0] != INFIX_WILDC) {
                return DPS_ERR_INVALID;
            }
            /*
             * Infix wildcard must be followed by a separator or NUL
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
 * A topic has the form \"A<sep>B<sep>C\" where \<sep\> is any of a specified set of separators and A, B, C are arbitrary
 * strings or the wild-card characters '+' or '#'. The '#' wild card if present can only appear as the last character.
 * Wildcards are only meaningful in subscriptions. The '+' wild card can appear anywhere including at the end of a
 * topic. These are all valid topic strings:
 *
 *    A/B/C/D
 *    A/+/C/D
 *    A/+/C/+
 *    A/#
 *    A/+/C
 *    +/+/+/+
 *
 * Note that when there are multiple topics in one publication, infix wildcard subscriptions are more prone to false
 * positives.  For example, if a single publication includes two topic strings A/B/1" and "C/D/2" the subscriptions
 * "A/+/2" or "C/+/1" will return false positive matches.
 *
 * This is because the bits representing prefixes "A/", "C/" and the suffixes "//2", "//1" are both present in the
 * publication Bloom filter.
 */
DPS_Status DPS_AddTopic(DPS_BitVector* bf, const char* topic, const char* separators, DPS_TopicType topicType)
{
    DPS_Status ret = DPS_OK;
    char* segment;
    int prefix = 0;
    const char* tp;
    const char* wc;
    size_t tlen;

    if (!bf || !topic || !separators) {
        return DPS_ERR_NULL;
    }
    tlen = strnlen(topic, DPS_MAX_TOPIC_STRLEN + 1);
    if (tlen > DPS_MAX_TOPIC_STRLEN) {
        DPS_ERRPRINT("Topic string too long\n");
        return DPS_ERR_INVALID;
    }
    if (strchr(separators, topic[0])) {
        DPS_ERRPRINT("Topic string cannot start with a separator\n");
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(topic, separators, topicType, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in topic string \"%s\"\n", topic);
        return ret;
    }
    tp = topic + strcspn(topic, separators);
    if (!wc) {
        DPS_BitVectorBloomInsert(bf, (const uint8_t*)topic, tlen);
        if (topicType != DPS_PubTopic) {
            return DPS_OK;
        }
    } else if (wc != topic) {
        DPS_BitVectorBloomInsert(bf, (const uint8_t*)topic, wc - topic);
    }
    segment = malloc(tlen + 1);
    if (!segment) {
        return DPS_ERR_RESOURCES;
    }
    while (*tp) {
        size_t len;
        segment[prefix++] = *tp++;
        if (topicType == DPS_PubTopic) {
            DPS_BitVectorBloomInsert(bf, (const uint8_t*)topic, tp - topic);
        }
        len = strcspn(tp, separators);
        if ((tp > wc) && (tp[0] != INFIX_WILDC || !tp[1])) {
            size_t sz = prefix + len;
            memcpy(segment + prefix, tp, len);
            segment[sz] = tp[len];
            if (tp[len]) {
                ++sz;
            }
            DPS_BitVectorBloomInsert(bf, (uint8_t*)segment, sz);
        }
        tp += len;
    }
    if (ret == DPS_OK) {
        if (topicType == DPS_PubTopic) {
            segment[prefix] = INFIX_WILDC;
            DPS_BitVectorBloomInsert(bf, (uint8_t*)segment, prefix + 1);
            while (prefix >= 0) {
                segment[prefix] = FINAL_WILDC;
                DPS_BitVectorBloomInsert(bf, (uint8_t*)segment, prefix + 1);
                --prefix;
            }
        }
    }
    free(segment);
    return ret;
}

int DPS_MatchTopic(DPS_BitVector* bf, const char* topic, const char* separators)
{
    static DPS_BitVector tmp;
    int match = DPS_FALSE;

    DPS_BitVectorClear(&tmp);
    if (DPS_AddTopic(&tmp, topic, separators, DPS_SubTopic) == DPS_OK) {
        match = DPS_BitVectorIncludes(bf, &tmp);
    }
    return match;
}

DPS_Status DPS_MatchTopicString(const char* pubTopic, const char* subTopic, const char* separators, int noWild, int* match)
{
    DPS_Status ret;
    const char* wc;

    if (!pubTopic || !subTopic || !separators || !match) {
        return DPS_ERR_NULL;
    }
    if (*pubTopic == 0 || *subTopic == 0 || *separators == 0) {
        return DPS_ERR_INVALID;
    }
    ret = CheckWildcarding(pubTopic, separators, DPS_PubTopic, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in PUB topic string\n");
        return ret;
    }
    ret = CheckWildcarding(subTopic, separators, DPS_SubTopic, &wc);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid use of wildcard in SUB topic string\n");
        return ret;
    }
    /*
     * Check if match is permitting wildcards
     */
    if (noWild && wc) {
        *match = DPS_FALSE;
        return DPS_OK;
    }
    *match = DPS_TRUE;
    while (*pubTopic && *subTopic) {
        if (ANY_WILDC(subTopic[0])) {
            size_t len = strcspn(pubTopic, separators);
            if (len) {
                pubTopic += len;
                if (subTopic[1] == 0) {
                    if (subTopic[0] == FINAL_WILDC) {
                        return DPS_OK;
                    }
                    if (subTopic[0] == INFIX_WILDC && pubTopic[0] == 0) {
                        return DPS_OK;
                    }
                }
            }
            ++subTopic;
        }
        if (*pubTopic != *subTopic) {
            *match = DPS_FALSE;
            break;
        }
        ++pubTopic;
        ++subTopic;
    }
    if (*subTopic || *pubTopic) {
        *match = DPS_FALSE;
    }
    return DPS_OK;
}

DPS_Status DPS_MatchTopicList(const char* const* pubs, size_t numPubs, const char* const* subs, size_t numSubs, const char* separators, int noWild, int* match)
{
    DPS_Status ret = DPS_ERR_INVALID;

    if (!pubs || !subs || !separators || !match) {
        return DPS_ERR_NULL;
    }
    *match = DPS_TRUE;
    while (numSubs--) {
        int ok = DPS_FALSE;
        size_t i;
        for (i = 0; i < numPubs; ++i) {
            ret = DPS_MatchTopicString(pubs[i], *subs, separators, noWild, &ok);
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

#ifdef DPS_DEBUG
void DPS_DumpTopics(const char** topics, size_t numTopics)
{
    if (DPS_Debug) {
        size_t i;
        for (i = 0; i < numTopics; ++i) {
            DPS_PRINT("%s\n", topics[i]);
        }
    }
}

void DPS_DumpMatchingTopics(DPS_BitVector* bv)
{
    char i;
    int match = 0;

    DPS_PRINT("[");
    for (i = 'A'; i <= 'Z'; ++i) {
        char topic[2] = { i, 0 };
        if (DPS_MatchTopic(bv, topic, ".")) {
            if (match++) {
                DPS_PRINT("|%c", i);
            } else {
                DPS_PRINT("%c", i);
            }
        }
    }
    DPS_PRINT("]\n");
}
#endif
