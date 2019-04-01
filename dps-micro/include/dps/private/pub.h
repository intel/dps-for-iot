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
 * Function prototype for a publication acknowledgement handler called when an acknowledgement
 * for a publication is received from a remote subscriber. The handler is called for each
 * subscriber that generates an acknowledgement so may be called numerous times for same
 * publication.
 *
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload accompanying the acknowledgement if any
 * @param len   Length of the payload
 */
typedef void (*DPS_AcknowledgementHandler)(DPS_Publication* pub, uint8_t* payload, size_t len);

/**
  * Function prototype for a publication send complete callback.
  *
  * @param pub     The publication that was sent
  * @param data    The data payload for the publication, it can now be freed
  * @param status  DPS_OK if the publication was sent to the network, otherwise and error status code.
  */

typedef void (*DPS_PublicationSendComplete)(DPS_Publication* pub, const uint8_t* data, DPS_Status status);

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
 * Initialize a publication and add it to the node. Storage for the publication must remain valid
 * until the publication is removed from the node by calling DPS_RemovePublication()
 *
 * A publication can be re-initialized without calling DPS_RemovePublication()
 * 
 * @param pub        The publication struct to initialize
 * @param topics     The topics to publish  - pointers to topic strings must remain valid for the lifetime of the publication
 * @param numTopics  The number of topics
 * @param noWildCard If TRUE subscription wildcard matching will be disallowed
 * @param ackHandler Handler for reporting acks. If NULL acks are not requested for this publication
 */
DPS_Status DPS_InitPublication(DPS_Node* node,
                               DPS_Publication* pub,
                               const char* topics[],
                               size_t numTopics,
                               int noWildCard,
                               const DPS_KeyId* keyId,
                               DPS_AcknowledgementHandler handler);

/**
  * Set a destination node address for a publication. If the address is non-null the
  * publication will be unicast to the specified node.
  *
  * @param pub    The publication to set the addresss on.
  * @param dest   The destination address for the publication, NULL to revert to multicast.
  * 
  * @return DPS_OK if the address was set.
  */
DPS_Status DPS_SetPublicationDestNode(DPS_Publication* pub, const DPS_NodeAddress* dest);

/**
  * Remove the publication and free any resources allocated for it.

  * @param pub        The publication to remove.
  */
DPS_Status DPS_RemovePublication(DPS_Publication* pub);

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
 * Send a publication. The publication will be multicast unless an address has been
 * set by calling DPS_SetPublicationAddr().
 *
 * @param pub             The publication to send.
 * @Param dest            An optional destination address, if non-NULL the publication is sent to
 *                        the specified node, otherwise it sent using IP multicast.
 * @param payload         An optional payload to send with the publication. The pointer to data must.
 *                        remain valid until the send complete callback is called.
 * @param len             Size of the payload.
 * @param ttl             Time for the publication to remain deliverable.
 * @param sendCompleteCB  Function called when the publication has been sent.
 *
 * @return DPS_OK if sending is successful, an error otherwise.
 */
DPS_Status DPS_Publish(DPS_Publication* pub,
                       const DPS_NodeAddress* dest,
                       const uint8_t* payload,
                       size_t len,
                       int16_t ttl,
                       DPS_PublicationSendComplete sendCompleteCB);

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

/**
  * Send an acknowledgement for a publication
  *
  * @param pub       The publication to acknowledge
  * @param data      An optional payload to send with the acknowledgment
  * @param len       Size of the payload
  *
  * @return DPS_OK if sending is successful, an error otherwise
  */
DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* data, size_t len);

/**
  * Did the sender of the publication request an ACK
  *
  * @param pub   The publication to check
  */
int DPS_PublicationIsAckRequested(const DPS_Publication* pub);

#ifdef __cplusplus
}
#endif

#endif
