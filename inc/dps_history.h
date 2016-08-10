#ifndef _DPS_HISTORY_H
#define _DPS_HISTORY_H

#include <stdint.h>
#include <stddef.h>
#include <dps.h>
#include <dps_uuid.h>

typedef struct _DPS_PubHistory {
    struct {
        uint32_t sn;
        DPS_UUID id;
        DPS_NodeAddress addr;
    } pub;
    uint64_t expiration;    /* Time when the history record can be deleted */
    struct _DPS_PubHistory* next;
} DPS_PubHistory;

typedef struct {
   DPS_PubHistory* oldest;  /* Oldest publication */
   DPS_PubHistory* newest;  /* Newest publication */
   uint32_t count;        
} DPS_History;

/**
 * Discards stale history information
 */
void DPS_FreshenHistory(DPS_History* history);

/**
 * Free all history
 */
void DPS_HistoryFree(DPS_History* history);

/**
 * Append a publication to the historical record
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param serialNumber  The serial number for the publication
 * @param addr          The address of the node that sent or forwarded this publication
 */
DPS_Status DPS_AppendPubHistory(DPS_History* history, DPS_UUID* pubId, uint32_t serialNumber, DPS_NodeAddress* addr);

/**
 * Check if a publication has been seen before
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param serialNumber  The serial number for the publication
 *
 * @return  Non zero if the exact publication has already been received.
 */
int DPS_PublicationIsStale(DPS_History* history, DPS_UUID* pubId, uint32_t serialNumber);

/**
 * Lookup a publisher address in the publication history. This is the address of the sender not 
 * necessarily the original publisher.
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param serialNumber  The serial number for the publication
 * @param addr          Returns the address of the publisher if there was a match
 *
 * @return DPS_OK if the sender was found in the history record
 *         DPS_ERR_MISSING if no sender was found in the history record
 */
DPS_Status DPS_LookupPublisher(DPS_History* history, DPS_UUID* pubId, uint32_t serialNumber, DPS_NodeAddress** addr);

#endif
