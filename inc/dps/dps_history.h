#ifndef _DPS_HISTORY_H
#define _DPS_HISTORY_H

#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <dps/dps_uuid.h>
#include <dps/dps_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DPS_NodeAddressList {
    uint32_t sn;
    DPS_NodeAddress addr;
    struct _DPS_NodeAddressList* next;
} DPS_NodeAddressList;

typedef struct _DPS_PubHistory {
    DPS_UUID id;
    uint32_t sn;
    uint8_t ackRequested;
    DPS_NodeAddressList* addrs;
    uint64_t expiration;    /* Time when the history record can be deleted */

    struct _DPS_PubHistory* left;
    struct _DPS_PubHistory* right;
    struct _DPS_PubHistory* parent;

    struct _DPS_PubHistory* prev;
    struct _DPS_PubHistory* next;
} DPS_PubHistory;

/**
 * Publication histories are stored in a binary tree and as a doubly linked
 * list sorted by expiration.
 */
typedef struct {
   uv_loop_t* loop;         /* same loop as the node loop */
   uv_mutex_t lock;         /* mutex to protect the history struct */
   DPS_PubHistory* root;    /* Root of binary tree */
   DPS_PubHistory* latest;  /* Latest publication to expire */
   DPS_PubHistory* soonest; /* Soonest publication to expire */
   uint32_t count;
} DPS_History;

/**
 * Discards stale history information
 */
void DPS_FreshenHistory(DPS_History* history);

/**
 * Free all history records
 */
void DPS_HistoryFree(DPS_History* history);

/**
 * Append a publication to the historical record
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param sequenceNum   The sequence number for the publication
 * @param ackRequested  TRUE if an ack was requested by the publisher
 * @param ttl           The ttl for the publication
 * @param addr          Optional address of the node that sent or forwarded this publication. This should
 *                      only be set for publications that are requesting an acknowledgment.
 */
DPS_Status DPS_UpdatePubHistory(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum, uint8_t ackRequested, uint16_t ttl, DPS_NodeAddress* addr);

/**
 * Check if a publication has been seen before
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param sequenceNum   The sequence number for the publication
 *
 * @return  Non zero if the exact publication has already been received.
 */
int DPS_PublicationIsStale(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum);

/**
 * Remove history for a specific publication
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 *
 * @return DPS_OK or DPS_ERR_MISSING if there is no history for this publication.
 */
DPS_Status DPS_DeletePubHistory(DPS_History* history, DPS_UUID* pubId);

/**
 * Lookup a publisher address in the publication history. This is the address of the sender not
 * necessarily the original publisher.
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param sequenceNum   Returns the sequence number for the matching publication
 * @param addr          Returns the address of the publisher if there was a match - might be NULL even if
 *                      there is a match.
 *
 * @return DPS_OK if the sender was found in the history record
 *         DPS_ERR_MISSING if no sender was found in the history record
 */
DPS_Status DPS_LookupPublisher(DPS_History* history, const DPS_UUID* pubId, uint32_t* sequenceNum, DPS_NodeAddress** addr);

/**
 * Determine if a publication has been received from the destination already.
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param source        The sender of the publication
 * @param destination   The intended receiver of the publication
 *
 * @return DPS_TRUE if publication has been received from destination, DPS_FALSE otherwise.
 */
int DPS_PublicationReceivedFrom(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum, DPS_NodeAddress* source, DPS_NodeAddress* destination);

#ifdef __cplusplus
}
#endif

#endif
