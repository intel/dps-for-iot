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

/**
 * Acknowledgement packet queued to be sent on node loop
 */
typedef struct _PublicationAck {
    DPS_Queue queue;                /**< Ack queue */
    DPS_TxBuffer buf;               /**< Headers, unprotected, and protected fields */
    DPS_TxBuffer encryptedBuf;      /**< Encrypted fields */
    DPS_NodeAddress destAddr;       /**< Destination of acknowledgement */
    uint32_t sequenceNum;           /**< Sequence number being acknowledged */
    DPS_UUID pubId;                 /**< The UUID of the publication */
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
 * @param node    The local node
 * @param ack     The acknowledgement to send
 * @param ackNode The remote node to send the acknowledgement to
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_SendAcknowledgement(DPS_Node*node, PublicationAck* ack, RemoteNode* ackNode);

/**
 * Free resources associated with an acknowledgement
 *
 * @param ack   The acknowledgement to destroy.
 */
void DPS_DestroyAck(PublicationAck* ack);

#ifdef __cplusplus
}
#endif

#endif
