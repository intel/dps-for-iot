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

#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <dps/err.h>
#include <dps/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define DPS_TRUE  1
#define DPS_FALSE 0

/**
 *
 */
#define DPS_MCAST_PUB_DISABLED       0
#define DPS_MCAST_PUB_ENABLE_SEND    1
#define DPS_MCAST_PUB_ENABLE_RECV    2


/**
 * Opaque type for a node
 */
typedef struct _DPS_Node DPS_Node;

/**
 * Opaque type for a remote node address.
 */
typedef struct _DPS_NodeAddress DPS_NodeAddress;

/**
 * Opaque type for a subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Get a topic for an active subscription
 *
 * @param sub   The subscription
 * @param index The topic index
 *
 * @return The topic string or NULL if the subscription or index is invalid.
 */
const char* DPS_SubscriptionGetTopic(const DPS_Subscription* sub, size_t index);

/**
 * Get the number of topics registered with an active subscription
 */
size_t DPS_SubscriptionGetNumTopics(const DPS_Subscription* sub);

/**
 * Opaque type for a publication
 */
typedef struct _DPS_Publication DPS_Publication;

/**
 * Get the UUID for a publication
 *
 * @param pub   The publication
 */
const DPS_UUID* DPS_PublicationGetUUID(const DPS_Publication* pub);

/**
 * Get the sequence number for a publication. Serial numbers are always > 0.
 *
 * @param pub   The publication
 *
 * @return The sequence number or zero if the publication is invalid.
 */
uint32_t DPS_PublicationGetSequenceNum(const DPS_Publication* pub);

/**
 * Get a topic for a publication
 *
 * @param pub   The publication
 * @param index The topic index
 *
 * @return The topic string or NULL if the publication or index is invalid.
 */
const char* DPS_PublicationGetTopic(const DPS_Publication* pub, size_t index);

/**
 * Get the number of topics in a publication
 *
 * @param pub   The publication
 */
size_t DPS_PublicationGetNumTopics(const DPS_Publication* pub);

/**
 * Get the local node associated with a publication
 *
 * @param pub   The publication
 *
 * @return  A pointer to the node or NULL if the publication is invalid
 */
DPS_Node* DPS_PublicationGetNode(const DPS_Publication* pub);

/**
 * Function prototype for callback function for requesting the encryption key
 * for a specific key identifier. This function must not block
 *
 * @param node    The node that is requesting the key
 * @param kid     The key identifier
 * @param key     Buffer for returning the key.
 * @param keyLen  Size of the key buffer
 *
 * @return  DPS_OK if a key matching the kid was returned
 *          DPS_ERR_MSSING if there is no matching key
 */
typedef DPS_Status (*DPS_KeyRequestCallback)(DPS_Node* node, DPS_UUID* kid, uint8_t* key, size_t keyLen);

/**
 * Allocates space for a local DPS node.
 *
 * @param separators    The separator characters to use for topic matching, if NULL defaults to "/"
 * @param keyRequestCB  Callback to request a decryption key
 * @param keyId         Encryption key id to use for publications sent from this node
 *
 * @return A pointer to the uninitialized node or NULL if there were no resources for the node.
 */
DPS_Node* DPS_CreateNode(const char* separators, DPS_KeyRequestCallback keyRequestCB, const DPS_UUID* keyId);

/**
 * Store a pointer to application data in a node.
 *
 * @param node   The node
 * @param data  The data pointer to store
 *
 * @return DPS_OK or and error
 */
DPS_Status DPS_SetNodeData(DPS_Node* node, void* data);

/**
 * Get application data pointer previously set by DPS_SetNodeData()
 *
 * @param node   The node
 *
 * @return  A pointer to the data or NULL if the node is invalid
 */
void* DPS_GetNodeData(const DPS_Node* node);

/**
 * Initialized and starts running a local node. Node can only be started once.
 * stopped.
 *
 * @param node         The node
 * @param mcastPub     Indicates if this node sends or listens for multicast publications
 * @param listenPort   If non-zero identifies specific port to listen on
 *
 * @return DPS_OK or various error status codes
 */
DPS_Status DPS_StartNode(DPS_Node* node, int mcastPub, int listenPort);

/**
 * Function prototype for callback function called when a node is destroyed.
 *
 * @param node   The node that was destroyed. This pointer is valid during 
 *               the callback.
 * @param data   Data pointer passed to DPS_DestroyNode()
 *
 */
typedef void (*DPS_OnNodeDestroyed)(DPS_Node* node, void* data);

/**
 * Destroys a node and free any resources.
 *
 * @param node   The node to destroy
 * @param cb     Callback function to be called when the node is destroyed
 * @param data   Data to be passed to the callback function
 *
 * @return -DPS_OK if the node will be destroyed and the callback called
 *         -DPS_ERR_NULL node or cb was a null pointer
 *         -Or an error status code in which case the callback will not be called.
 */
DPS_Status DPS_DestroyNode(DPS_Node* node, DPS_OnNodeDestroyed cb, void* data);

/**
 * Get the uv event loop for this node. The only thing that is safe to do with the node
 * is to create an async callback. Other libuv APIs can then be called from within the
 * async callback.
 *
 * @param node     The local node to use
 */
uv_loop_t* DPS_GetLoop(DPS_Node* node);

/**
 * Function prototype for a publication acknowledgment handler called when an acknowledgement
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
 * Allocates storage for a publication
 *
 * @param node         The local node to use
 */
DPS_Publication* DPS_CreatePublication(DPS_Node* node);

/**
 * Creates a partial copy of a publication that can be used to acknowledge the publication.
 * The copy is not useful for anything other than in a call to DPS_AckPublication() and should
 * be freed by calling DPS_DestroyPublcation() when no longer needed.
 *
 * The partial copy can be used with DPS_PublicationGetUUID() and DPS_PublicationGetSequenceNum()
 *
 * @param pub  The publication to copy
 *
 * @return A partial copy of the publication or NULL if the publication could not be copied.
 */
DPS_Publication* DPS_CopyPublication(const DPS_Publication* pub);

/**
 * Store a pointer to application data in a publication.
 *
 * @param pub   The publication
 * @param data  The data pointer to store
 *
 * @return DPS_OK or and error
 */
DPS_Status DPS_SetPublicationData(DPS_Publication* pub, void* data);

/**
 * Get application data pointer previously set by DPS_SetPublicationData()
 *
 * @param pub   The publication
 *
 * @return  A pointer to the data or NULL if the publication is invalid
 */
void* DPS_GetPublicationData(const DPS_Publication* pub);

/**
 * Initializes a newly created publication with a set of topics. Each publication has a UUID and a
 * sequence number. The sequence number is incremented each time the publication is published. This
 * allows subscriber to determine that publications received form a series. The acknowledgment
 * handler is optional, if present the publication is marked as requesting acknowledgment and that
 * information is provided to the subscribers.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 *
 * @param pub         The the publication to initialize
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish - must be >= 1
 * @param noWildCard  If TRUE the publication will not match wildcard subscriptions
 * @param handler     Optional handler for receiving acknowledgments
 */
DPS_Status DPS_InitPublication(DPS_Publication* pub, const char** topics, size_t numTopics, int noWildCard, DPS_AcknowledgementHandler handler);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately
 * to matching subscribers and then re-published whenever a new matching subscription is received.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.  Call
 * the accessor function DPS_PublicationGetSequenceNum() to get the current sequence number for this
 * publication. The sequence number is incremented each time DPS_Publish() is called for the same
 * publication.
 *
 * @param pub          The publication to send
 * @param pubPayload   Optional payload
 * @param len          Length of the payload
 * @param ttl          Time to live in seconds - maximum TTL is about 9 hours
 *
 * @return - DPS_OK if the topics were succesfully published
 */
DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* pubPayload, size_t len, int16_t ttl);

/**
 * Delete a publication and frees any resources allocated. This does not cancel retained publications
 * that have an unexpired TTL. To expire a retained publication call DPS_Publish() with a zero TTL.
 *
 * This function should only be called for publications created by DPS_CreatePublication() or 
 * DPS_CopyPublication().
 *
 * @param pub         The publication to destroy
 */
DPS_Status DPS_DestroyPublication(DPS_Publication* pub);

/**
 * Function prototype for a publication handler called when a publication is received that
 * matches a subscription. Note that there is a possibilitly of false-positive matches.
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
 * Aknowledge a publication. A publication should be acknowledged as soon as possible after receipt
 * ideally from within the publication handler callback function. If the publication cannot be
 * acknowedged immediately in the publication handler callback, call DPS_CopyPublication() to make a
 * partial copy of the publication that can be passed to this function at a later time.
 *
 * @param pub           The publication to acknowledge
 * @param ackPayload    Optional payload to accompany the aknowledgment
 * @param len           The length of the payload
 */
DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* ackPayload, size_t len);

/**
 * Get the local node associated with a publication
 *
 * @param pub   A publication
 *
 * @return  Returns the local node associated with a publication
 */
DPS_Node* DPS_GetPublicationNode(const DPS_Publication* pub);

/**
 * Allocate memory for a subscription and initialize topics
 *
 * @param node         The local node to use
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match - must be >= 1
 *
 * @return   Returns a pointer to the newly created subscription or NULL if resources
 *           could not be allocated or the arguments were invalid
 */
DPS_Subscription* DPS_CreateSubscription(DPS_Node* node, const char** topics, size_t numTopics);

/**
 * Store a pointer to application data in a subscription.
 *
 * @param sub   The subscription
 * @param data  The data pointer to store
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetSubscriptionData(DPS_Subscription* sub, void* data);

/**
 * Get application data pointer previously set by DPS_SetSubscriptionData()
 *
 * @param sub   The subscription
 *
 * @return  A pointer to the data or NULL if the subscription is invalid
 */
void* DPS_GetSubscriptionData(DPS_Subscription* sub);

/**
 * Get the local node associated with a subscription
 *
 * @param sub   The subscription
 *
 * @return  A pointer to the node or NULL if the subscription is invalid
 */
DPS_Node* DPS_SubscriptionGetNode(const DPS_Subscription* sub);

/**
 * Start subscribing to a set of topics
 *
 * @param sub          The subscription to start
 * @param handler      Callback function to be called with topic matches
 */
DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler);

/**
 * Stop subscribing to the subscription topic and free resources allocated for the subscription
 *
 * @param sub   The subscription to cancel
 */
DPS_Status DPS_DestroySubscription(DPS_Subscription* sub);

/**
 * Function prototype for function called when a DPS_Link() completes.
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node that was linked
 * @param status Indicates if the link completed or failed
 * @param data   Application data passed in the call to DPS_Link()
 */
typedef void (*DPS_OnLinkComplete)(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data);

/**
 * Link the local node to a remote node
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node to link to
 * @param cb     The callback function to call on completion, can be NULL which case the function is synchronous
 * @param data   Application data to be passed to the callback

 * @return DPS_OK or an error status. If an error status is returned the callback function will not be called.
 */
DPS_Status DPS_Link(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnLinkComplete cb, void* data);

/**
 * Function prototype for function called when a DPS_Unlink() completes.
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node that was unlinked
 * @param data   Application data passed in the call to DPS_Link()
 */
typedef void (*DPS_OnUnlinkComplete)(DPS_Node* node, DPS_NodeAddress* addr, void* data);

/**
 * Unlink the local node from a remote node
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node to unlink from
 * @param cb     The callback function to call on completion, can be NULL which case the function is synchronous
 * @param data   Application data to be passed to the callback
 *
 * @return DPS_OK or an error status. If an error status is returned the callback function will not be called.
 */
DPS_Status DPS_Unlink(DPS_Node* node, DPS_NodeAddress* addr, DPS_OnUnlinkComplete cb, void* data);

/**
 * Get the port number this node is listening for connections on
 *
 * @param node     The local node to use
 */
uint16_t DPS_GetPortNumber(DPS_Node* node);

/**
 * Function prototype for function called when a DPS_ResolveAddress() completes.
 *
 * @param node   The local node to use
 * @param addr   The resolved address or NULL if the address could not be resolved
 * @param data   Application data passed in the call to DPS_ResolveAddress()
 */
typedef void (*DPS_OnResolveAddressComplete)(DPS_Node* node, DPS_NodeAddress* addr, void* data);

/**
 * Resolve a host name or IP address and service name or port number.
 *
 * @param node     The local node to use
 * @param host     The host name or IP address to resolve
 * @param service  The port or service name to resolve
 * @param cb       The callback function to call on completion
 * @param data     Application data to be passed to the callback
 *
 * @return DPS_OK or an error status. If an error status is returned the callback function will not be called.
 */
DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service, DPS_OnResolveAddressComplete cb, void* data);

/**
 * Get text representation of an address. This function uses a static string buffer so is not thread safe.
 *
 * @param addr to get the text for
 *
 * @return  A text string for the address
 */
const char* DPS_NodeAddrToString(DPS_NodeAddress* addr);

/**
 * Creates an node address.
 */
DPS_NodeAddress* DPS_CreateAddress();

/**
 * Set a node address
 *
 * @param addr  The address to set
 * @param sa    The value to set
 *
 * @return The addr passed in.
 */
DPS_NodeAddress* DPS_SetAddress(DPS_NodeAddress* addr, const struct sockaddr* sa);

/**
 * Copy a node address
 */
void DPS_CopyAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src);

/**
 * Frees resources associated with an address
 */
void DPS_DestroyAddress(DPS_NodeAddress* addr);

/**
 * Returns a non-secure random number
 */
uint32_t DPS_Rand();

#ifdef __cplusplus
}
#endif

#endif
