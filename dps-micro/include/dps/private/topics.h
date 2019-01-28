/**
 * @file
 * Topic strings
 */

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

#ifndef _TOPICS_H
#define _TOPICS_H

#include <dps/private/dps.h>
#include <dps/private/bitvec.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum length for a topic string excluding NUL terminator
 */
#define DPS_MAX_TOPIC_STRLEN 2048

/**
 * Enumeration for Pub and Sub topicTypes
 *
 * DPS_SubTopic encode the bloom filter bits for a subscription
 * DPS_PubTopic encode the bloom filter bits for a publication allowing wild-card matching
 * DPS_PubNoWild is for publications that do not permit wild-card matches
 */
typedef enum { DPS_SubTopic, DPS_PubTopic, DPS_PubNoWild } DPS_TopicType;

/**
 * Add a topic to a Bloom filter.  A topic has the general form \"A<sep>B<sep>C...\"
 * where \<sep\> is any of a specified set of separators and A, B, C are
 * arbitrary strings or a standalone wild-card character "*"
 *
 * @param bf          The Bloom filter to add the topic to
 * @param topic       The topic to add
 * @param separators  The separator strings for the topic
 * @param topicType   The type encoding for the topic string being added
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_AddTopic(DPS_BitVector* bf, const char* topic, const char* separators, DPS_TopicType topicType);

/**
 * Check a bloom filter for a topic match.
 *
 * @param bf          The Bloom filter to match against
 * @param topic       The topic to match
 * @param separators  The separator strings for the topic
 *
 * @return DPS_TRUE if there was match, DPS_FALSE if there was not a match.
 */
int DPS_MatchTopic(DPS_BitVector* bf, const char* topic, const char* separators);

/**
 * String based topic matching
 *
 * @param pubTopic    The publication topic
 * @param subTopic    The subscription topic to match
 * @param separators  The separator strings for the topic
 * @param noWild      Wild card matches are disallowed
 * @param match       Returns 1 for a match and 0 for no match
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_MatchTopicString(const char* pubTopic, const char* subTopic, const char* separators, int noWild, int* match);

/**
 * String based topic matching. The publication topics must provide a match for all of the subscription topics
 *
 * @param pubs        The array of publication topics
 * @param numPubs     Size of the pubs array
 * @param subs        The array of subscription topics to match
 * @param numSubs     Size of the subs array
 * @param separators  The separator strings for the topics
 * @param noWild      Wild card matches are disallowed
 * @param match       Returns 1 for a match and 0 for no match
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_MatchTopicList(const char* const* pubs, size_t numPubs, const char* const* subs, size_t numSubs, const char* separators, int noWild, int* match);

#ifdef DPS_DEBUG
/**
 * Print out topic strings
 *
 * @param topics The topic strings
 * @param numTopics The number of topic strings
 */
void DPS_DumpTopics(const char** topics, size_t numTopics);

/**
 * Print out all topics 'A' to 'Z' that match the given bit vector.
 * This is useful for debugging DPS routing issues.
 *
 * @param bv The bit vector
 */
void DPS_DumpMatchingTopics(DPS_BitVector* bv);
#else
#define DPS_DumpTopics(t, n)
#define DPS_DumpMatchingTopics(b)
#endif


#ifdef __cplusplus
}
#endif

#endif
