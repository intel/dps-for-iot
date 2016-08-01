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
 */
DPS_Status DPS_AppendPubHistory(DPS_History* history, DPS_UUID* pubId, uint32_t serialNumber);

/**
 * Check is a publication has been seen before
 */
int DPS_PublicationIsStale(DPS_History* history, DPS_UUID* pubId, uint32_t serialNumber);

#endif
