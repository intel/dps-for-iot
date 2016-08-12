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
 * Enumeration for Pub and Sub roles
 */
typedef enum { DPS_Sub, DPS_Pub } DPS_Role;

/**
 * Opaque type for a node
 */
typedef struct _DPS_Node DPS_Node;

/**
 * Type for an address
 */
typedef struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
} DPS_NodeAddress;

/**
 * Returns static string for a node address
 */
#define DPS_NodeAddressText(a) DPS_NetAddrText((struct sockaddr*)a)

/**
 * Opaque type for an active subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Get a topic for an active subscription
 */
const char* DPS_SubscriptionGetTopic(DPS_Node* node, const DPS_Subscription* sub, size_t index);

/**
 * Get the number of topics registered with an active subscription
 */
size_t DPS_SubscriptionGetNumTopics(DPS_Node* node, const DPS_Subscription* sub);

/**
 * Opaque type for an active publication
 */
typedef struct _DPS_Publication DPS_Publication;

/**
 * Get the UUID for a publication
 */
const DPS_UUID* DPS_PublicationGetUUID(DPS_Node* node, const DPS_Publication* pub);

/**
 * Get the serial number for a publication. Serial numbers are always > 0.
 *
 * @param node         The local node for this publication
 * @param pub
 *
 * @return The serial number or zero if the publication is invalid.
 */
uint32_t DPS_PublicationGetSerialNumber(DPS_Node* node, const DPS_Publication* pub);

/**
 * For passing buffers around
 */
typedef struct {
    uint8_t* base; /**< base address for buffer */
    uint8_t* eod;  /**< end of buffer or data */
    uint8_t* pos;  /**< current read/write location in buffer */
} DPS_Buffer;

/**
 * Initialize a buffer struct
 *
 * @param buffer    Buffer to initialized
 * @param storage   The storage for the buffer. If the storage is NULL storage is allocated.
 * @param size      Current size of the buffer
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if storage is needed and could not be allocated.
 */
DPS_Status DPS_BufferInit(DPS_Buffer* buffer, uint8_t* storage, size_t size);

/*
 * Space left in a buffer being written
 */
#define DPS_BufferSpace(b)  ((b)->eod - (b)->pos)

/*
 * Data available in a buffer being read
 */
#define DPS_BufferAvail(b)  ((b)->eod - (b)->pos)

/*
 * Space currently used in buffer
 */
#define DPS_BufferUsed(b)  ((b)->pos - (b)->base)


#define DPS_MCAST_PUB_DISABLED       0
#define DPS_MCAST_PUB_ENABLE_SEND    1
#define DPS_MCAST_PUB_ENABLE_RECV    2

/**
 * Initialize a local node
 *
 * @param mcastPub     Indicates if this node sends or listens for multicast publications
 * @param tcpPort      If non-zero identifies specific port to listen on
 * @param separators   The separator characters to use for topic matching, typically '/' and/or '.'
 */
DPS_Node* DPS_InitNode(int mcastPub, int tcpPort, const char* separators);

/**
 * Get the uv event loop for this node
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
 * @param node     The local node used in the publish call
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload accompanying the acknowledgement if any
 * @param len   Length of the payload
 */
typedef void (*DPS_AcknowledgementHandler)(DPS_Node* node, const DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Create a new publication from a set of topics. Each publication has a UUID and a serial number. The
 * serial number of incremented each time the publication is published. This allows subscriber to
 * determine that publications received form a series. The acknowledgment handler is optional, if
 * present the publication is marked as requesting acknowledgment and that information is provided
 * to the subscribers.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 *
 * @param node        The local node to use
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish
 * @param handler     Optional handler for receiving acknowledgments
 * @param pub         Returns an opaque handle that can be used to cancel the publication later
 */
DPS_Status DPS_CreatePublication(DPS_Node* node, char* const* topics, size_t numTopics, DPS_AcknowledgementHandler handler, DPS_Publication** pub);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately to matching
 * subscribers and then re-published whenever a new matching subscription is received.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 * Call the accessor function DPS_PublicationGetSerialNumber() to get the current serial number for this
 * publication. The serial number is incremented each time DPS_Publish() is called for the same
 * publication.
 *
 * @param node         The local node to use
 * @param pub          The publication to send
 * @param payload      Optional payload 
 * @param len          Length of the payload
 * @param ttl          Time to live in seconds - maximum TTL is about 9 hours
 * @param oldPayload   Returns pointer to payload passed to previous call to DPS_Pubish() 
 *
 * @return - DPS_OK if the topics were succesfully published
 */
DPS_Status DPS_Publish(DPS_Node* node, DPS_Publication* pub, void* payload, size_t len, int16_t ttl, void** oldPayload);

/**
 * Delete a local publication and frees any resources allocated. This does not cancel retained publications that have an
 * unexpired TTL. To expire a retained publication call DPS_Publish() with a zero TTL.
 *
 * @param node     The local node to use
 * @param pub      The publication to destroy
 * @param payload  Returns pointer to last payload passed to DPS_Pubish()
 */
DPS_Status DPS_DestroyPublication(DPS_Node* node, DPS_Publication* pub, void** payload);

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
 *
 * @param node     The local node used in the subscribe call
 * @param sub      Opaque handle for the subscription that was matched
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload from the publication if any
 * @param len      Length of the payload
 */
typedef void (*DPS_PublicationHandler)(DPS_Node* node, DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Aknowledge a publication. A publication should be acknowledged as soon as possible after receipt ideally from within the publication
 * handler callback function. 
 *
 * @param node          The local node that received the publication
 * @param pubId         The UUID of the publication to acknowledge
 * @param serialNumber  The serial number of the publication to acknowledge
 * @param payload       Optional payload to accompany the aknowledgment
 * @param len           The length of the payload
 */
DPS_Status DPS_AcknowledgePublication(DPS_Node* node, const DPS_UUID* pubId, uint32_t serialNumber, void* payload, size_t len);

/**
 * Susbscribe to one or more topics. All topics must match
 *
 * @param node         The local node to use
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match
 * @param handler      Callback function to be called with matching topics
 * @param sub          Returns an opaque handle that can be used to cancel the subscription
 */
DPS_Status DPS_Subscribe(DPS_Node* node, char* const* topics, size_t numTopics, DPS_PublicationHandler handler, DPS_Subscription** sub);

/**
 * Cancel subscription to a topic
 *
 * @param node  The local node to use
 * @param sub   The subscription to cancel
 */
DPS_Status DPS_SubscribeCancel(DPS_Node* node, DPS_Subscription* sub);

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
 * Terminate a local node and free any associated resources.
 *
 * @param node   The node to terminate
 */
void DPS_TerminateNode(DPS_Node* node);

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
 * @oaran addr          Returns the resolved address
 */
DPS_Status DPS_ResolveAddress(DPS_Node* node, const char* host, const char* service, DPS_NodeAddress* addr);

/**
 * Print the current subscriptions
 */
void DPS_DumpSubscriptions(DPS_Node* node);


#endif
