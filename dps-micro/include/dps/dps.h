/**
 * @file
 * Public APIs
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

#ifndef _DPS_H
#define _DPS_H

#include <dps/targets.h>
#include <stdint.h>
#include <stddef.h>
#include <dps/err.h>
#include <dps/keystore.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_TRUE  1 /**< TRUE boolean value */
#define DPS_FALSE 0 /**< FALSE boolean value */

/**
 * Opaque type for a subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Opaque type for a publication
 */
typedef struct _DPS_Publication DPS_Publication;

/**
 * Opaque type for a remote node address.
 */
typedef struct _DPS_NodeAddress DPS_NodeAddress;

/**
 * Function prototype for a publication handler called when a publication is received that
 * matches a subscription. Note that there is a possibility of false-positive matches.
 *
 * The publication handle is only valid within the body of this callback function.
 * DPS_CopyPublication() will make a partial copy of the publication that can be used later for
 * example to call DPS_AckPublication().
 *
 * The accessor functions DPS_PublicationGetUUID() and DPS_PublicationGetSequenceNum()
 * return information about the received publication.
 *
 * The accessor functions DPS_SubscriptionGetNumTopics() and DPS_SubscriptionGetTopic()
 * return information about the subscription that was matched.
 *
 * @param sub      Opaque handle for the subscription that was matched
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload from the publication if any
 * @param len      Length of the payload
 */
typedef void (*DPS_PublicationHandler)(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Opaque type for a DPS node
 */
typedef struct _DPS_Node DPS_Node;

/**
  * Create the node
  */
DPS_Node* DPS_CreateNode(const char* separators);

/**
  * Start the node
  */
DPS_Status DPS_Start(DPS_Node* node);

/**
  * Destroy the node
  */
void DPS_DestroyNode(DPS_Node* node);

/**
  * Get the port number the node is listening on
  */
uint16_t DPS_GetPortNumber(DPS_Node* node);

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
 * Initialize a publication and add it to the node.
 *
 * @param topics     The topics to publish  - pointers to topic strings must remain valid for the lifetime of the publication
 * @param numTopics  The number of topics
 * @param noWildCard If TRUE subscription wildcard matching will be disallowed
 * @param ackHandler Handler for reporting acks. If NULL acks are not requested for this publication
 * 
 * @return  Return an initialized publication or NULL if the publication can not be initialized
 */
DPS_Publication* DPS_InitPublication(DPS_Node* node,
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
  * Delete the publication and free any resources allocated for it.
  *
  * @param pub   The publication to delete.
  */
void DPS_DestroyPublication(DPS_Publication* pub);

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
 * Function prototype for a publication handler called when a publication is received that
 * matches a subscription. Note that there is a possibility of false-positive matches.
 *
 * The publication handle is only valid within the body of this callback function.
 * DPS_CopyPublication() will make a partial copy of the publication that can be used later for
 * example to call DPS_AckPublication().
 *
 * The accessor functions DPS_PublicationGetUUID() and DPS_PublicationGetSequenceNum()
 * return information about the received publication.
 *
 * The accessor functions DPS_SubscriptionGetNumTopics() and DPS_SubscriptionGetTopic()
 * return information about the subscription that was matched.
 *
 * @param sub      Opaque handle for the subscription that was matched
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload from the publication if any
 * @param len      Length of the payload
 */
typedef void (*DPS_PublicationHandler)(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Allocate memory for a subscription and initialize topics
 *
 * @param node         The DPS node
 * @param topics       The topics to subscribe to  - pointers to topic strings must remain valid
 *                     for the lifetime of the subscription
 * @param numTopics    The number of topic strings - must be >= 1
 *
 * @return A pointer to an initialized subscription or NULL if the initialization failed
 */
DPS_Subscription* DPS_InitSubscription(DPS_Node* node, const char* const* topics, size_t numTopics);

/**
 * Activate a subscription
 *
 * @param sub      The subscription to activate
 * @param handler  Callback function to call when a matching publication is received
 * @param data     Data to be passed to the callback function
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler, void* data);

/**
 * Deactivate a subscription and release any allocated resources.
 *
 * @param sub      The subscription to destroy
 */
void DPS_DestroySubscription(DPS_Subscription* sub);

/**
  * Disable DTLS - this should be called before any DTLS connections are established
  */
DPS_Status DPS_DisableDTLS(DPS_Node* node);

/**
 * Get text representation of an address.
 *
 * @note This function uses a static string buffer so it not thread safe.
 *
 * @param addr to get the text for
 *
 * @return A text string for the address
 */
const char* DPS_NodeAddrToString(const DPS_NodeAddress* addr);

/**
  * Allocate and initialize a node address.
  *
  * @param host   The host IP address
  * @param port   The port number
  *
  * @return  An initialized node address or NULL if the initialization failed.
  */
DPS_NodeAddress* DPS_InitNodeAddress(const char* host, uint16_t port);

/**
 * Release resources allocation for a node address
 *
 * @param addr  The node address to destroy
 */
void DPS_DestroyNodeAddress(DPS_NodeAddress* addr);

/**
  * Get the node pointer from a publication
  *
  * @param pub   Pointer to a publication
  * @return   A pointer to a node or NULL if pub is not a valid publication pointer
  */
DPS_Node* DPS_PubGetNode(DPS_Publication* pub);

/**
  * Get the node pointer from a subscription
  *
  * @param sub   Pointer to a subscription
  * @return   A pointer to a node or NULL if sub is not a valid subscription pointer
  */
DPS_Node* DPS_SubGetNode(DPS_Subscription* sub);

/**
  * Make the local node discoverable to other nodes. Does nothing if the node
  * is already discoverable.
  *
  * @param  node       Pointer to a node
  * @param  serviceId  Pointer to the service identifier. If NULL a default
  *                    service id is used.

  * @return DPS_OK if the node was made discoverable, otherwise an error status
  */
DPS_Status DPS_MakeDiscoverable(DPS_Node* node, const char* serviceId);

/**
  * Make the the local node no longer discoverable. Has no effect if the node is
  * not currently discoverable.
  */
void DPS_MakeNondiscoverable(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif
