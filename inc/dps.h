#ifndef _DPS_H
#define _DPS_H

#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <dps_err.h>
#include <dps_uuid.h>

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
 * Opaque type for an address
 */
typedef struct _DPS_NodeAddress DPS_NodeAddress;

/**
 * Opaque type for a subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Get a topic for an active subscription
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
 * Opaque type for a publication acknowledgement
 */
typedef struct _DPS_PublicationAck DPS_PublicationAck;

/**
 * Get the UUID for a publication
 */
const DPS_UUID* DPS_PublicationGetUUID(const DPS_Publication* pub);

/**
 * Get the serial number for a publication. Serial numbers are always > 0.
 *
 * @param pub
 *
 * @return The serial number or zero if the publication is invalid.
 */
uint32_t DPS_PublicationGetSerialNumber(const DPS_Publication* pub);

/**
 * Allocates space for a local DPS node.
 *
 * @param separators   The separator characters to use for topic matching, if NULL defaults to "/"
 *
 * @return A pointer to the uninitialized node or NULL if there were no resources for the node.
 */
DPS_Node* DPS_CreateNode(const char* separators);

/**
 * Initialized and starts running a local node. Node can only be started once and cannot be restarted after it has been
 * stopped.
 *
 * @param mcastPub     Indicates if this node sends or listens for multicast publications
 * @param tcpPort      If non-zero identifies specific port to listen on
 *
 * @return DPS_OK or various error status codes
 */
DPS_Status DPS_StartNode(DPS_Node* node, int mcastPub, int tcpPort);

/**
 * Stop a local node. This can be called from any thread. The node must be stopped before it can be destroyed.
 *
 * @param node   The node to stop
 */
void DPS_StopNode(DPS_Node* node);

/**
 * Waits for the node to stop and destroys node and free any resources.
 *
 * Note: if not waiting for the node to stop call DPS_StopNode() first.
 *
 * @param node   The node to destroy
 */
void DPS_DestroyNode(DPS_Node* node);

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
 * Initializes a newly created publication with a set of topics. Each publication has a UUID and a serial number. The
 * serial number of incremented each time the publication is published. This allows subscriber to
 * determine that publications received form a series. The acknowledgment handler is optional, if
 * present the publication is marked as requesting acknowledgment and that information is provided
 * to the subscribers.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 *
 * @param pub         The the publication to initialize
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish - must be >= 1
 * @param handler     Optional handler for receiving acknowledgments
 */
DPS_Status DPS_InitPublication(DPS_Publication* pub, char* const* topics, size_t numTopics, DPS_AcknowledgementHandler handler);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately to matching
 * subscribers and then re-published whenever a new matching subscription is received.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 * Call the accessor function DPS_PublicationGetSerialNumber() to get the current serial number for this
 * publication. The serial number is incremented each time DPS_Publish() is called for the same
 * publication.
 *
 * @param pub          The publication to send
 * @param pubPayload   Optional payload
 * @param len          Length of the payload
 * @param ttl          Time to live in seconds - maximum TTL is about 9 hours
 * @param oldPayload   Returns pointer to payload passed to previous call to DPS_Pubish()
 *
 * @return - DPS_OK if the topics were succesfully published
 */
DPS_Status DPS_Publish(DPS_Publication* pub, uint8_t* pubPayload, size_t len, int16_t ttl, uint8_t** oldPayload);

/**
 * Delete a local publication and frees any resources allocated. This does not cancel retained publications that have an
 * unexpired TTL. To expire a retained publication call DPS_Publish() with a zero TTL.
 *
 * @param pub      The publication to destroy
 * @param payload  Returns pointer to last payload passed to DPS_Pubish()
 */
DPS_Status DPS_DestroyPublication(DPS_Publication* pub, uint8_t** oldPayload);

/**
 * Function prototype for a publication handler called when a publication is received that
 * matches a subscription. Note that there is a possibilitly of false-positive matches.
 *
 * The publication handle is only valid within the body of this callback function.
 *
 * The accessor functions DPS_PublicationGetUUID() and DPS_PublicationGetSerialNumber()
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
 * Create an aknowledgement for a publication.
 *
 * @param pub  The publication that will be acknowledged.
 */
DPS_PublicationAck* DPS_CreatePublicationAck(const DPS_Publication* pub);

/**
 * Aknowledge a publication. A publication should be acknowledged as soon as possible after receipt ideally from within the publication
 * handler callback function.
 *
 * @param ack           The acknowledgment
 * @param ackPayload    Optional payload to accompany the aknowledgment
 * @param len           The length of the payload
 */
DPS_Status DPS_AckPublication(DPS_PublicationAck* ack, uint8_t* ackPayload, size_t len);

/**
 * Free resources associated with an publication acknowledgement
 *
 * @param ack  The acknowledgment to destroy
 */
DPS_Status DPS_DestroyPublicationAck(DPS_PublicationAck* ack);

/**
 * Allocate memory for a subscription and initialize topics
 *
 * @param node         The local node to use
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match - must be >= 1
 *
 * @param return   Returns a pointer to the newly created subscription or NULL if resources
 *                 could not be allocated or the arguments were invalid
 */
DPS_Subscription* DPS_CreateSubscription(DPS_Node* node, char* const* topics, size_t numTopics);

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
 * Join the local node to a remote node
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node to join
 */
DPS_Status DPS_Join(DPS_Node* node, DPS_NodeAddress* addr);

/**
 * Remove a remote node.
 *
 * @param node   The local node to use
 * @param addr   The address of a remote node
 */
DPS_Status DPS_Leave(DPS_Node* node, DPS_NodeAddress* addr);

/**
 * Get the port number this node is listening for connections on
 *
 * @param node          The local node to use
 */
uint16_t DPS_GetPortNumber(DPS_Node* node);

/**
 * Wrapper around uv_getaddrinfo
 *
 * @param node          The local node to use
 * @param host          The host name or IP address to resolve
 * @param service       The port or service name to resolve
 *
 * @return addr  Returns the address or NULL if the address could not be resolved
 */
DPS_NodeAddress* DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service);

/**
 * Get text representation of an address. This function uses a static string buffer so it not thread safe.
 *
 * @param Address to get the text for
 *
 * @return  A text string for the address
 */
const char* DPS_GetAddressText(DPS_NodeAddress* addr);

/**
 * Frees resources associated with an address
 */
void DPS_DestroyAddress(DPS_NodeAddress* addr);

#endif
