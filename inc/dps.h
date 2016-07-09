#ifndef _DPS_H
#define _DPS_H

#include <stdint.h>
#include <stddef.h>
#include <uv.h>
#include <dps_err.h>

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
    uint16_t port;     /* Port number in host order */
    uint8_t addr[16];  /* IPv6 address */
} DPS_NodeAddress;

/**
 * Returns static string for a node address
 */
const char* DPS_NodeAddressText(const DPS_NodeAddress* addr);

/**
 * Opaque type for an active subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Opaque type for an active publication
 */
typedef struct _DPS_Publication DPS_Publication;

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

/**
 * Initialize a local node
 *
 * @param mcastListen  If non-zero initializes the node for multicast reception
 * @param tcpPort      If non-zero identifies specific port to listen on
 * @param separators   The separator characters to use for topic matching, typically '/' and/or '.'
 */
DPS_Node* DPS_InitNode(int mcastListen, int tcpPort, const char* separators);

/**
 * Get the uv event loop for this node
 *
 * @param node     The local node to use
 */
uv_loop_t* DPS_GetLoop(DPS_Node* node);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately and then
 * re-published whenever an updated subscription is received.
 *
 * @param node        The local node to use
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish
 * @param publication Returns an opaque handle that can be used to cancel the publication later
 * @param data        Optional data - this must remain valid until the publication is canceled
 * @param len         Length of the optional data
 */
DPS_Status DPS_Publish(DPS_Node* node, char* const* topics, size_t numTopics, DPS_Publication** pub, void* data, size_t len);

/**
 * Cancel publishing a topic.
 *
 * @param node         The local node to use
 * @param publication  The publication to cancel
 * @param data         Address passed in when DPS_Pubish() was called
 */
DPS_Status DPS_PublishCancel(DPS_Node* node, DPS_Publication* pub, void** data);

/**
 * Function prototype for a subscription match callback
 *
 * @param node          The local node used in the subscribe call
 * @param subscription  Opaque handle for the subscription
 * @param topics        The topics that were matched 
 * @param numTopics     The number of topics
 * @param addr          The address of the node that reported the match
 * @param data          Payload from the publication if any
 * @param len           Length of the payload
 */
typedef void (*DPS_MatchHandler)(DPS_Node* node,
                                 DPS_Subscription* sub,
                                 const char** topics,
                                 size_t numTopics,
                                 const DPS_NodeAddress* addr,
                                 uint8_t* data,
                                 size_t len);

/**
 * Susbscribe to one or more topics. All topics must match
 *
 * @param node         The local node to use
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match
 * @param handler      Callback function to be called with matching topics
 * @param subscription Returns an opaque handle that can be used to cancel the subscription
 */
DPS_Status DPS_Subscribe(DPS_Node* node, char* const* topics, size_t numTopics, DPS_MatchHandler handler, DPS_Subscription** sub);

/**
 * Cancel subscription to a topic
 *
 * @param node          The local node to use
 * @param subscription  The subscription to cancel
 */
DPS_Status DPS_SubscribeCancel(DPS_Node* node, DPS_Subscription* sub);

/**
 * Join a publisher. Subscriptions are pushed to the new publisher.
 *
 * @param node         The local node to use
 * @param addr         The address of a publisher to join
 */
DPS_Status DPS_Join(DPS_Node* node, DPS_NodeAddress* addr);

/**
 * Remove a publisher.
 *
 * @param node         The local node to use
 * @param addr         The address of a publisher to leave
 */
DPS_Status DPS_Leave(DPS_Node* node, DPS_NodeAddress* addr);

/**
 * Terminate a node and free any associated resources.
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
