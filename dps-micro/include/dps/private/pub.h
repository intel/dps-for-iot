/**
 * @file
 * Send and receive publication messages
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

#ifndef _PUB_H
#define _PUB_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include <dps/private/cose.h>
#include <dps/private/bitvec.h>
#include <dps/private/node.h>
#include <dps/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation configured maximum number of topic strings in a publication
 */
#define MAX_PUB_TOPICS    8

/**
 * Implementation configured maximum number of recipient IDs 
 */
#define MAX_PUB_RECIPIENTS  4

/**
 * Struct for a publication
 */
struct _DPS_Publication {
    DPS_Node* node;                             /**< Node for this publication */
    void* userData;                             /**< Application provided user data */
    uint8_t ackRequested;                       /**< TRUE if an ack was requested by the publisher */
    DPS_AcknowledgementHandler handler;         /**< Called when an acknowledgement is received from a subscriber */
    DPS_UUID pubId;                             /**< Unique publication identifier */
    DPS_NodeAddress* fromAddr;                  /**< Address of node that sent the publication */
    uint32_t sequenceNum;                       /**< Sequence number for this publication */
    COSE_Entity recipients[MAX_PUB_RECIPIENTS]; /**< Publication recipient IDs */
    size_t numRecipients;                       /**< Number of recipients IDs */
    DPS_BitVector bf;                           /**< The Bloom filter bit vector for the topics for this publication */
    const char* topics[MAX_PUB_TOPICS];         /**< Topic strings */
    size_t numTopics;                           /**< Number of topic strings */
    COSE_Entity sender;                         /**< Publication sender ID */
    COSE_Entity ack;                            /**< For ack messages - the ack sender ID */
    DPS_PublicationSendComplete sendCompleteCB; /**< Publication completion callback */
    const uint8_t* payload;                     /**< Saved pointer for payload to pass to completion callback */
    DPS_Publication* next;                      /**< Linked list of publications */
};

/**
 * Decode and process a received publication.
 *
 * @param node       The local node.
 * @param pub        The publication struct to receive the decoded publication.
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise.
 */
DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf);

/**
 * Look for a publication matching the ID and sequence number.
 *
 * @param node The node.
 * @param pubId The ID to look for.
 * @param sequenceNum The sequence number to look for.
 *
 * @return The matching publication or NULL.
 */
DPS_Publication* DPS_LookupAckHandler(DPS_Node* node, const DPS_UUID* pubId, uint32_t sequenceNum);

#ifdef __cplusplus
}
#endif

#endif
