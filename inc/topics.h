#ifndef _TOPICS_H
#define _TOPICS_H

#include <bitvec.h>
#include <dps_internal.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Add a topic to a Bloom filter.  A topic has the general form "A<sep>B<sep>C..."
 * where <sep> is any of a specified set of separators and A, B, C are
 * arbitrary strings or a standalone wild-card character "*"
 *
 * @param bf          The Bloom filter to add the topic to
 * @param topic       The topic to add
 * @param separators  The separator strings for the topic
 * @param role        DPS_Pub or DPS_Sub
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_AddTopic(DPS_BitVector* bf, const char* topic, const char* separators, DPS_Role role);

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
 * @param match       Returns 1 for a match and 0 for no match
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_MatchTopicString(const char* pubTopic, const char* subTopic, const char* separators, int* match);

/**
 * String based topic matching. The publication topics must provide a match for all of the subscription topics
 *
 * @param pubs        The array of publication topics
 * @param numPubs     Size of the pubs array
 * @param subs        The array of subscription topics to match 
 * @param numSubs     Size of the subs array
 * @param separators  The separator strings for the topics
 * @param match       Returns 1 for a match and 0 for no match
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_MatchTopicList(char* const* pubs, size_t numPubs, char* const* subs, size_t numSubs, const char* separators, int* match);

#ifdef __cplusplus
}
#endif

#endif
