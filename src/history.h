/**
 * @file
 * Publication histories
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

#ifndef _DPS_HISTORY_H
#define _DPS_HISTORY_H

#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A list of node addresses and sequence numbers
 */
typedef struct _DPS_NodeAddressList {
    uint32_t sn;                /**< A sequence number */
    uint16_t hopCount;          /**< A hop count */
    DPS_NodeAddress addr;       /**< A node address */
    struct _DPS_NodeAddressList* next; /**< The next address in the list */
} DPS_NodeAddressList;

/**
 * A publication history
 */
typedef struct _DPS_PubHistory {
    DPS_UUID id;                /**< The UUID for the publication */
    uint32_t sn;                /**< The sequence number for the publication */
    uint8_t ackRequested;       /**< DPS_TRUE if publisher has requested an acknowledgement */
    DPS_NodeAddressList* addrs; /**< Addresses of nodes that sent or forwarded this publication */
    uint64_t expiration;    /**< Time when the history record can be deleted */

    struct _DPS_PubHistory* left; /**< Left child in publication history binary tree */
    struct _DPS_PubHistory* right; /**< Right child in publication history binary tree  */
    struct _DPS_PubHistory* parent; /**< Parent in publication history binary tree */

    struct _DPS_PubHistory* prev; /**< Previous history in expiration-sorted list */
    struct _DPS_PubHistory* next; /**< Next history in expiration-sorted list */
} DPS_PubHistory;

/**
 * Publication histories are stored in a binary tree and as a doubly linked
 * list sorted by expiration.
 */
typedef struct {
   uv_loop_t* loop;         /**< same loop as the node loop */
   uv_mutex_t lock;         /**< mutex to protect the history struct */
   DPS_PubHistory* root;    /**< Root of binary tree */
   DPS_PubHistory* latest;  /**< Latest publication to expire */
   DPS_PubHistory* soonest; /**< Soonest publication to expire */
   uint32_t count;          /**< Number of histories stored */
} DPS_History;

/**
 * Discards stale history information
 *
 * @param history       The history from a local node
 */
void DPS_FreshenHistory(DPS_History* history);

/**
 * Free all history records
 *
 * @param history       The history from a local node
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
 * @param hopCount      The hop count for the publication
 * @param addr          Optional address of the node that sent or forwarded this publication. This should
 *                      only be set for publications that are requesting an acknowledgement.
 *
 * @return DPS_OK if update is successful, an error otherwise
 */
DPS_Status DPS_UpdatePubHistory(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum, uint8_t ackRequested, uint16_t ttl, uint16_t hopCount, DPS_NodeAddress* addr);

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
 * Lookup a publisher address in the publication history to match an acknowledgement. This is the
 * address of the sender not necessarily the original publisher.
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
DPS_Status DPS_LookupPublisherForAck(DPS_History* history, const DPS_UUID* pubId, uint32_t* sequenceNum, DPS_NodeAddress** addr);

/**
 * Determine if a publication has been received from the destination already.
 *
 * @param history       The history from a local node
 * @param pubId         The UUID for the publication
 * @param sequenceNum   The sequence number for the publication
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
