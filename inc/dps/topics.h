#ifndef _TOPICS_H
#define _TOPICS_H

#include <dps/bitvec.h>
#include <dps/dps_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 * @return - DPS_TRUE is there was match, DPS_FALSE is there was not a match.
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
DPS_Status DPS_MatchTopicList(char* const* pubs, size_t numPubs, char* const* subs, size_t numSubs, const char* separators, int noWild, int* match);

#ifdef __cplusplus
}
#endif

#endif
