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
    struct sockaddr_in6 ip6;
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
 * Publish a set of topics along with an optional payload. The topics will be published immediately to matching
 * subscribers and then re-published whenever a new matching subscription is received.
 *
 * @param node        The local node to use
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish
 * @param pub         Returns an opaque handle that can be used to cancel the publication later
 */
DPS_Status DPS_CreatePublication(DPS_Node* node, char* const* topics, size_t numTopics, DPS_Publication** pub);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately to matching
 * subscribers and then re-published whenever a new matching subscription is received.
 *
 * If the previous publication had a non-zero TTL this publication will cause and retained publications to expire.
 *
 * @param node         The local node to use
 * @param publication  The publication to send
 * @param payload      Optional payload 
 * @param len          Length of the payload
 * @param ttl          Time to live in seconds - maximum TTL is about 9 hours
 * @param oldPayload   Returns pointer to payload passed to previous call to DPS_Pubish() 
 */
DPS_Status DPS_Publish(DPS_Node* node, DPS_Publication* pub, void* payload, size_t len, int16_t ttl, void** oldPayload);

/**
 * Delete a local publication and frees any resources allocated. This does not cancel retained publications that have an
 * unexpired TTL. To expire a retained publication call DPS_Publish() with a zero TTL.
 *
 * @param node         The local node to use
 * @param publication  The publication to destroy
 * @param payload      Returns pointer to last payload passed to DPS_Pubish()
 */
DPS_Status DPS_DestroyPublication(DPS_Node* node, DPS_Publication* pub, void** payload);

/**
 * Function prototype for a subscription match callback
 *
 * @param node          The local node used in the subscribe call
 * @param subscription  Opaque handle for the subscription
 * @param topics        The topics that were matched 
 * @param numTopics     The number of topics
 * @param data          Payload from the publication if any
 * @param len           Length of the payload
 */
typedef void (*DPS_MatchHandler)(DPS_Node* node,
                                 DPS_Subscription* sub,
                                 const char** topics,
                                 size_t numTopics,
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
 * Join the local node to a remote publisher.
 *
 * @param node         The local node to use
 * @param addr         The address of the publisher to join
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
