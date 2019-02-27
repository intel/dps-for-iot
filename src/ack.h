/**
 * @file
 * Send and receive acknowledgement messages
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

#ifndef _ACK_H
#define _ACK_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include "node.h"
#include "queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_INTERNAL_ACK_BUFS 4 /**< Additional buffers needed for message serialization */

/**
 * Acknowledgement packet queued to be sent on node loop
 */
typedef struct _PublicationAck {
    DPS_Queue queue;                    /**< Ack queue */
    DPS_Publication* pub;               /**< The publication being acknowledged */
    DPS_NodeAddress destAddr;           /**< Destination of acknowledgement */
    uint32_t sequenceNum;               /**< Sequence number being acknowledged */
    DPS_PublishBufsComplete completeCB; /**< The completion callback */
    void* data;                         /**< Context pointer */
    DPS_Status status;                  /**< Result of the publish */
    size_t numBufs;                     /**< Number of buffers */
    /**
     * Ack fields.
     *
     * Usage of the buffers is as follows:
     * 0:            DPS headers, unprotected, and protected fields
     * 1:            COSE headers (may be empty)
     * 2:            Payload headers
     * 3..numBufs-2: Payload
     * numBufs-1:    COSE footers (may be empty)
     */
    DPS_TxBuffer bufs[1];
} PublicationAck;

/**
 * Decode and process a received acknowledgement
 *
 * @param node    The local node
 * @param ep      The endpoint the acknowledgement was received on
 * @param buffer  The encoded acknowledgement
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeAcknowledgement(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer);

/**
 * Send an previously serialized acknowledgement
 *
 * Must be called with the node lock held.
 *
 * @param ack     The acknowledgement to send
 * @param ackNode The remote node to send the acknowledgement to
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_SendAcknowledgement(PublicationAck* ack, RemoteNode* ackNode);

/**
 * Complete the ack when finished.
 *
 * @param ack The acknowledgement
 */
void DPS_AckPublicationCompletion(PublicationAck* ack);

#ifdef __cplusplus
}
#endif

#endif
