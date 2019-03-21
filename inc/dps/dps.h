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

#include <stdint.h>
#include <stddef.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include <dps/err.h>
#include <dps/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_TRUE  1 /**< TRUE boolean value */
#define DPS_FALSE 0 /**< FALSE boolean value */

/**
 * @defgroup nodeaddress Node Address
 * Remote node addresses.
 * @{
 */

/**
 * Opaque type for a remote node address.
 */
typedef struct _DPS_NodeAddress DPS_NodeAddress;

/**
 * Get text representation of an address. This function uses a static
 * string buffer so is not thread safe.
 *
 * @param addr to get the text for
 *
 * @return A text string for the address
 */
const char* DPS_NodeAddrToString(const DPS_NodeAddress* addr);

/**
 * Creates a node address.
 *
 * @return The created address, or NULL if creation failed
 */
DPS_NodeAddress* DPS_CreateAddress(void);

/**
 * Set a node address
 *
 * @param addr        The address to set
 * @param addrText    The text string for the address
 *
 * @return The addr passed in, or NULL if an error occurred
 */
DPS_NodeAddress* DPS_SetAddress(DPS_NodeAddress* addr, const char* addrText);

/**
 * Copy a node address
 *
 * @param dest The address to copy to.
 * @param src  The address to copy from.
 */
void DPS_CopyAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src);

/**
 * Frees resources associated with an address
 *
 * @param addr A previously created address.
 */
void DPS_DestroyAddress(DPS_NodeAddress* addr);

/** @} */ /* end of nodeaddress group */

/**
 * @defgroup keystore Key Store
 * Key stores provide key data for protecting messages and the
 * network.
 * @{
 */

/**
 * @name KeyStore
 * Hooks for implementing an application-defined key store.
 * @{
 */

/**
 * A DPS key type
 */
typedef enum {
    DPS_KEY_SYMMETRIC,          /**< DPS_KeySymmetric */
    DPS_KEY_EC,                 /**< DPS_KeyEC */
    DPS_KEY_EC_CERT             /**< DPS_KeyCert */
} DPS_KeyType;

/**
 * Symmetric key data
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeySymmetric {
    const uint8_t* key;         /**< Key data */
    size_t len;                 /**< Size of key data */
} DPS_KeySymmetric;

#define DPS_AES_256_KEY_LEN 32 /**< AES 256 key length, in bytes */

/**
 * Allowed elliptic curves
 */
typedef enum {
    DPS_EC_CURVE_RESERVED = 0,
    DPS_EC_CURVE_P384 = 2, /**< NIST P-384 also known as secp384r1 */
    DPS_EC_CURVE_P521 = 3  /**< NIST P-521 also known as secp521r1 */
} DPS_ECCurve;

/**
 * Elliptic curve key data.
 *
 * Only @p x and @p y are needed for a public key.  Similarly, only @p
 * d is needed for a private key.
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeyEC {
    DPS_ECCurve curve; /**< The named curve */
    const uint8_t* x; /**< X coordinate */
    const uint8_t* y; /**< Y coordinate */
    const uint8_t* d; /**< D coordinate */
} DPS_KeyEC;

/**
 * Certificate key data.
 *
 * @note Need to define this outside of DPS_Key to satisfy SWIG.
 */
typedef struct _DPS_KeyCert {
    const char *cert;           /**< The certificate in PEM format */
    const char *privateKey;     /**< The optional private key in PEM format */
    const char *password;       /**< The optional password protecting the key */
} DPS_KeyCert;

/**
 * Union of supported key types.
 */
typedef struct _DPS_Key {
    DPS_KeyType type; /**< Type of key */
    /** Value of key */
    union {
        DPS_KeySymmetric symmetric; /**< DPS_KEY_SYMMETRIC */
        DPS_KeyEC ec;               /**< DPS_KEY_EC */
        DPS_KeyCert cert;           /**< DPS_KEY_EC_CERT */
    };
} DPS_Key;

/**
 * An identifier of a key in a key store.
 */
typedef struct _DPS_KeyId {
    const uint8_t* id; /**< the identifier of the key */
    size_t len; /**< the length of the identifier, in bytes */
} DPS_KeyId;

/**
 * Opaque type for a key store.
 */
typedef struct _DPS_KeyStore DPS_KeyStore;

/**
 * Opaque type for a key store request.
 */
typedef struct _DPS_KeyStoreRequest DPS_KeyStoreRequest;

/**
 * Function prototype for a key store handler called when a key and
 * key identifier is requested.
 *
 * DPS_SetKeyAndId() should be called to provide the key and
 * identifier to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 *
 * @return
 * - DPS_OK when DPS_SetKeyAndId() succeeds
 * - DPS_ERR_MISSING when no key is configured for this host
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyAndIdHandler)(DPS_KeyStoreRequest* request);

/**
 * Function prototype for a key store handler called when a key with the provided
 * key identifier is requested.
 *
 * DPS_SetKey() should be called to provide the key to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 * @param keyId The identifier of the key to provide.
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_KeyHandler)(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);

/**
 * Function prototype for a key store handler called when an ephemeral key with the
 * provided type is requested.
 *
 * DPS_SetKey() should be called to provide the ephemeral key to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 * @param key The requested key type and parameters (e.g. key->type is
 *            DPS_KEY_EC and key->ec.curve is DPS_EC_CURVE_P521).
 *
 * @return
 * - DPS_OK when DPS_SetKey() succeeds
 * - DPS_ERR_MISSING when no key is located
 * - error otherwise
 */
typedef DPS_Status (*DPS_EphemeralKeyHandler)(DPS_KeyStoreRequest* request, const DPS_Key* key);

/**
 * Function prototype for a key store handler called when the trusted
 * CA chain is requested.
 *
 * DPS_SetCA() should be called to provide the CA chain to the caller.
 *
 * @param request The request, only valid with the body of this
 *                callback function.
 *
 * @return
 * - DPS_OK when DPS_SetCA() succeeds
 * - DPS_ERR_MISSING when no CA chain is configured
 * - error otherwise
 */
typedef DPS_Status (*DPS_CAHandler)(DPS_KeyStoreRequest* request);

/**
 * Provide a key and key identifier to a key store request.
 *
 * @param request The @p request parameter of the handler
 * @param key The key
 * @param keyId The identifier of the key to provide
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetKeyAndId(DPS_KeyStoreRequest* request, const DPS_Key* key, const DPS_KeyId* keyId);

/**
 * Provide a key to a key store request.
 *
 * @param request The @p request parameter of the handler
 * @param key The key
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetKey(DPS_KeyStoreRequest* request, const DPS_Key* key);

/**
 * Provide a trusted CA chain to a key store request.
 *
 * @param request The @p request parameter of the handler
 * @param ca The CA chain in PEM format
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetCA(DPS_KeyStoreRequest* request, const char* ca);

/**
 * Returns the @p DPS_KeyStore* of a key store request.
 *
 * @param request A key store request
 *
 * @return The DPS_KeyStore* or NULL
 */
DPS_KeyStore* DPS_KeyStoreHandle(DPS_KeyStoreRequest* request);

/**
 * Creates a key store.
 *
 * @param keyAndIdHandler Optional handler for receiving key and key
 *                        identifier requests
 * @param keyHandler Optional handler for receiving key requests
 * @param ephemeralKeyHandler Optional handler for receiving ephemeral
 *                            key requests
 * @param caHandler Optional handler for receiving CA chain requests
 *
 * @return The key store or NULL if there were no resources.
 */
DPS_KeyStore* DPS_CreateKeyStore(DPS_KeyAndIdHandler keyAndIdHandler, DPS_KeyHandler keyHandler,
                                 DPS_EphemeralKeyHandler ephemeralKeyHandler, DPS_CAHandler caHandler);

/**
 * Destroys a previously created key store.
 *
 * @param keyStore The key store
 */
void DPS_DestroyKeyStore(DPS_KeyStore* keyStore);

/**
 * Store a pointer to application data in a key store.
 *
 * @param keyStore The key store
 * @param data The data pointer to store
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetKeyStoreData(DPS_KeyStore* keyStore, void* data);

/**
 * Get application data pointer previously set by DPS_SetKeyStoreData().
 *
 * @param keyStore The keyStore
 *
 * @return A pointer to the data or NULL if the key store is invalid
 */
void* DPS_GetKeyStoreData(const DPS_KeyStore* keyStore);

/** @} */ /* end of KeyStore subgroup */

/**
 * @name In-memory Key Store
 * The implementation of an in-memory key store.
 * @{
 */

/**
 * Opaque type for an in-memory key store.
 */
typedef struct _DPS_MemoryKeyStore DPS_MemoryKeyStore;

/**
 * Creates an in-memory key store.
 *
 * @return The key store or NULL if there were no resources.
 */
DPS_MemoryKeyStore* DPS_CreateMemoryKeyStore(void);

/**
 * Destroys a previously created in-memory key store.
 *
 * @param keyStore An in-memory key store
 */
void DPS_DestroyMemoryKeyStore(DPS_MemoryKeyStore* keyStore);

/**
 * Create or replace a key with the specified key identifier in the key store.
 *
 * Specify a previously set key identifier and a NULL key to remove a key from the key store.
 *
 * @param keyStore An in-memory key store
 * @param keyId The identifier of the key to create, replace, or remove
 * @param key The key
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetContentKey(DPS_MemoryKeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key);

/**
 * Create or replace the network key in the key store.
 *
 * @param keyStore An in-memory key store
 * @param keyId The identifier of the key to create
 * @param key The key
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetNetworkKey(DPS_MemoryKeyStore* keyStore, const DPS_KeyId* keyId, const DPS_Key* key);

/**
 * Create or replace the trusted CA(s) in the key store.
 *
 * @param mks An in-memory key store
 * @param ca The CA chain in PEM format
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetTrustedCA(DPS_MemoryKeyStore* mks, const char* ca);

/**
 * Create or replace a certificate in the key store.
 *
 * @param mks An in-memory key store
 * @param cert The certificate in PEM format
 * @param key The optional private key in PEM format
 * @param password The optional password protecting the key, may be
 *                 NULL
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetCertificate(DPS_MemoryKeyStore* mks, const char* cert, const char* key,
                              const char* password);

/**
 * Returns the @p DPS_KeyStore* of an in-memory key store.
 *
 * @param keyStore An in-memory key store
 *
 * @return The DPS_KeyStore* or NULL
 */
DPS_KeyStore* DPS_MemoryKeyStoreHandle(DPS_MemoryKeyStore* keyStore);

/** @} */ /* end of MemoryKeyStore subgroup */

/** @} */ /* end of keystore group */

/**
 * @defgroup node Node
 * Entities in the DPS network.
 * @{
 */

/**
 * Opaque type for a node.
 */
typedef struct _DPS_Node DPS_Node;

/**
 * Allocates space for a local DPS node.
 *
 * @param separators    The separator characters to use for topic matching, if NULL defaults to "/"
 * @param keyStore      The key store to use for this node
 * @param keyId         The key identifier of this node
 *
 * @return The uninitialized node or NULL if there were no resources for the node.
 */
DPS_Node* DPS_CreateNode(const char* separators, DPS_KeyStore* keyStore, const DPS_KeyId* keyId);

/**
 * Store a pointer to application data in a node.
 *
 * @param node   The node
 * @param data  The data pointer to store
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetNodeData(DPS_Node* node, void* data);

/**
 * Get application data pointer previously set by DPS_SetNodeData()
 *
 * @param node   The node
 *
 * @return A pointer to the data or NULL if the node is invalid
 */
void* DPS_GetNodeData(const DPS_Node* node);

/**
 * Disable multicast send and receive on the node.  See @p mcastPub of DPS_StartNode().
 */
#define DPS_MCAST_PUB_DISABLED       0

/**
 * Enable multicast send on the node.  See @p mcastPub of DPS_StartNode().
 */
#define DPS_MCAST_PUB_ENABLE_SEND    1

/**
 * Enable multicast receive on the node.  See @p mcastPub of DPS_StartNode().
 */
#define DPS_MCAST_PUB_ENABLE_RECV    2

/**
 * Initialized and starts running a local node. Node can only be started once.
 *
 * @param node         The node
 * @param mcastPub     Indicates if this node sends or listens for multicast publications
 * @param listenAddr   If non-NULL identifies specific address to listen on
 *
 * @return DPS_OK or various error status codes
 */
DPS_Status DPS_StartNode(DPS_Node* node, int mcastPub, DPS_NodeAddress* listenAddr);

/**
 * Function prototype for callback function called when a node is destroyed.
 *
 * @param node   The node that was destroyed. This node is valid during
 *               the callback.
 * @param data   Data passed to DPS_DestroyNode()
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
 * @return
 * - DPS_OK if the node will be destroyed and the callback called
 * - DPS_ERR_NULL node or cb was null
 * - Or an error status code in which case the callback will not be called.
 */
DPS_Status DPS_DestroyNode(DPS_Node* node, DPS_OnNodeDestroyed cb, void* data);

/**
 * The default maximum rate (in msecs) to compute and send out subscription updates.
 */
#define DPS_SUBSCRIPTION_UPDATE_RATE 1000

/**
 * Specify the time delay (in msecs) between subscription updates.
 *
 * @param node           The node
 * @param subsRateMsecs  The time delay (in msecs) between updates
 */
void DPS_SetNodeSubscriptionUpdateDelay(DPS_Node* node, uint32_t subsRateMsecs);

/**
 * Get the address this node is listening for connections on
 *
 * @param node     The node
 *
 * @return The address
 */
const DPS_NodeAddress* DPS_GetListenAddress(DPS_Node* node);

/**
 * Get text representation of the address this node is listening for
 * connections on. This function uses a static string buffer so is not
 * thread safe.
 *
 * @param node     The node
 *
 * @return A text string for the address
 */
const char* DPS_GetListenAddressString(DPS_Node* node);

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
 * @param node     The local node to use
 * @param addrText The text string of the address to link to
 * @param cb       The callback function to call on completion, can be NULL which case the function is synchronous
 * @param data     Application data to be passed to the callback
 *
 * @return DPS_OK or an error status. If an error status is returned the callback function will not be called.
 */
DPS_Status DPS_Link(DPS_Node* node, const char* addrText, DPS_OnLinkComplete cb, void* data);

/**
 * Function prototype for function called when a DPS_Unlink() completes.
 *
 * @param node   The local node to use
 * @param addr   The address of the remote node that was unlinked
 * @param data   Application data passed in the call to DPS_Unlink()
 */
typedef void (*DPS_OnUnlinkComplete)(DPS_Node* node, const DPS_NodeAddress* addr, void* data);

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
DPS_Status DPS_Unlink(DPS_Node* node, const DPS_NodeAddress* addr, DPS_OnUnlinkComplete cb, void* data);

/**
 * Function prototype for function called when a DPS_ResolveAddress() completes.
 *
 * @param node   The local node to use
 * @param addr   The resolved address or NULL if the address could not be resolved
 * @param data   Application data passed in the call to DPS_ResolveAddress()
 */
typedef void (*DPS_OnResolveAddressComplete)(DPS_Node* node, const DPS_NodeAddress* addr, void* data);

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

/** @} */ /* end of node group */

/**
 * @defgroup publication Publication
 * Publications.
 * @{
 */

/**
 * Opaque type for a publication
 */
typedef struct _DPS_Publication DPS_Publication;

/**
 * Get the UUID for a publication
 *
 * @param pub   The publication
 *
 * @return The UUID if publication is valid, or NULL otherwise
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
 *
 * @return The number of topics.
 */
size_t DPS_PublicationGetNumTopics(const DPS_Publication* pub);

/**
 * Check if an acknowledgement was requested for a publication.
 *
 * @param pub   The publication
 *
 * @return 1 if an acknowledgement was requested, otherwise 0.
 */
int DPS_PublicationIsAckRequested(const DPS_Publication* pub);

/**
 * Get the key identifier of a publication
 *
 * @param pub   The publication
 *
 * @return The key identifier of the publisher, may be NULL
 */
const DPS_KeyId* DPS_PublicationGetSenderKeyId(const DPS_Publication* pub);

/**
 * Get the local node associated with a publication
 *
 * @param pub   The publication
 *
 * @return The node or NULL if the publication is invalid
 */
DPS_Node* DPS_PublicationGetNode(const DPS_Publication* pub);

/**
 * Allocates storage for a publication
 *
 * @param node         The local node to use
 *
 * @return The newly created publication, or NULL if creation failed
 */
DPS_Publication* DPS_CreatePublication(DPS_Node* node);

/**
 * Creates a partial copy of a publication that can be used to acknowledge the publication.
 * The copy is not useful for anything other than in a call to DPS_AckPublication() and should
 * be freed by calling DPS_DestroyPublication() when no longer needed.
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
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetPublicationData(DPS_Publication* pub, void* data);

/**
 * Get application data pointer previously set by DPS_SetPublicationData()
 *
 * @param pub   The publication
 *
 * @return A pointer to the data or NULL if the publication is invalid
 */
void* DPS_GetPublicationData(const DPS_Publication* pub);

/**
 * Function prototype for a publication acknowledgement handler called when an acknowledgement
 * for a publication is received from a remote subscriber. The handler is called for each
 * subscriber that generates an acknowledgement so may be called numerous times for same
 * publication.
 *
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload accompanying the acknowledgement if any
 * @param len      Length of the payload
 */
typedef void (*DPS_AcknowledgementHandler)(DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Initializes a newly created publication with a set of topics. Each publication has a UUID and a
 * sequence number. The sequence number is incremented each time the publication is published. This
 * allows subscriber to determine that publications received form a series. The acknowledgement
 * handler is optional, if present the publication is marked as requesting acknowledgement and that
 * information is provided to the subscribers.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.
 *
 * @param pub         The the publication to initialize
 * @param topics      The topic strings to publish
 * @param numTopics   The number of topic strings to publish - must be >= 1
 * @param noWildCard  If TRUE the publication will not match wildcard subscriptions
 * @param keyId       Optional key identifier to use for encrypted publications
 * @param handler     Optional handler for receiving acknowledgements
 *
 * @return DPS_OK if initialization is successful, an error otherwise
 */
DPS_Status DPS_InitPublication(DPS_Publication* pub,
                               const char** topics,
                               size_t numTopics,
                               int noWildCard,
                               const DPS_KeyId* keyId,
                               DPS_AcknowledgementHandler handler);

/**
 * Adds a key identifier to use for encrypted publications.
 *
 * @param pub         The the publication to initialize
 * @param keyId       Key identifier to use for encrypted publications
 *
 * @return DPS_OK if addition is successful, an error otherwise
 */
DPS_Status DPS_PublicationAddSubId(DPS_Publication* pub, const DPS_KeyId* keyId);

/**
 * Removes a key identifier to use for encrypted publications.
 *
 * @param pub         The the publication to initialize
 * @param keyId       Key identifier to remove
 */
void DPS_PublicationRemoveSubId(DPS_Publication* pub, const DPS_KeyId* keyId);

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
 * @return DPS_OK if the topics were successfully published
 */
DPS_Status DPS_Publish(DPS_Publication* pub, const uint8_t* pubPayload, size_t len, int16_t ttl);

/**
 * A buffer.
 */
typedef struct _DPS_Buffer {
    uint8_t* base;              /**< Pointer to the base of the buffer */
    size_t len;                 /**< Length of the buffer */
} DPS_Buffer;

/**
 * Called when DPS_PublishBufs() completes.
 *
 * @param pub     The publication
 * @param bufs    The payload buffers passed to DPS_PublishBufs()
 * @param numBufs The number of payload buffers passed to DPS_PublishBufs()
 * @param status  The status of the publish
 * @param data    Application data passed to DPS_PublishBufs()
 */
typedef void (*DPS_PublishBufsComplete)(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                                        DPS_Status status, void* data);

/**
 * Publish a set of topics along with an optional payload. The topics will be published immediately
 * to matching subscribers and then re-published whenever a new matching subscription is received.
 *
 * Call the accessor function DPS_PublicationGetUUID() to get the UUID for this publication.  Call
 * the accessor function DPS_PublicationGetSequenceNum() to get the current sequence number for this
 * publication. The sequence number is incremented each time DPS_Publish() is called for the same
 * publication.
 *
 * @note When the ttl is greater than zero, the callback function will not be called until the
 * publication expires, is replaced by a subsequent call to DPS_PublishBufs(), is canceled, or is
 * destroyed.
 *
 * @param pub          The publication to send
 * @param bufs         Optional payload buffers - this memory must remain valid until the callback
 *                     function is called
 * @param numBufs      The number of buffers
 * @param ttl          Time to live in seconds - maximum TTL is about 9 hours
 * @param cb           Callback function called when the publish is complete
 * @param data         Data to be passed to the callback function
 *
 * @return DPS_OK if the topics were successfully published
 */
DPS_Status DPS_PublishBufs(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, int16_t ttl,
                           DPS_PublishBufsComplete cb, void* data);

/**
 * Delete a publication and frees any resources allocated. This does not cancel retained publications
 * that have an unexpired TTL. To expire a retained publication call DPS_Publish() with a zero TTL.
 *
 * This function should only be called for publications created by DPS_CreatePublication() or
 * DPS_CopyPublication().
 *
 * @param pub         The publication to destroy
 *
 * @return DPS_OK if destroy is successful, an error otherwise
 */
DPS_Status DPS_DestroyPublication(DPS_Publication* pub);

/**
 * Acknowledge a publication. A publication should be acknowledged as soon as possible after receipt,
 * ideally from within the publication handler callback function. If the publication cannot be
 * acknowledged immediately in the publication handler callback, call DPS_CopyPublication() to make a
 * partial copy of the publication that can be passed to this function at a later time.
 *
 * @param pub           The publication to acknowledge
 * @param ackPayload    Optional payload to accompany the acknowledgement
 * @param len           The length of the payload
 *
 * @return DPS_OK if acknowledge is successful, an error otherwise
 */
DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* ackPayload, size_t len);

/**
 * Called when DPS_AckPublicationBufs() completes.
 *
 * @param pub     The publication
 * @param bufs    The payload buffers passed to DPS_AckPublicationBufs()
 * @param numBufs The number of payload buffers passed to DPS_AckPublicationBufs()
 * @param status  The status of the publish
 * @param data    Application data passed to DPS_AckPublicationBufs()
 */
typedef void (*DPS_AckPublicationBufsComplete)(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                                               DPS_Status status, void* data);

/**
 * Acknowledge a publication. A publication should be acknowledged as soon as possible after receipt,
 * ideally from within the publication handler callback function. If the publication cannot be
 * acknowledged immediately in the publication handler callback, call DPS_CopyPublication() to make a
 * partial copy of the publication that can be passed to this function at a later time.
 *
 * @param pub           The publication to acknowledge
 * @param bufs          Optional payload buffers - this memory must remain valid until the callback
 *                      function is called
 * @param numBufs       The number of buffers
 * @param cb            Callback function called when the acknowledge is complete
 * @param data          Data to be passed to the callback function
 *
 * @return DPS_OK if acknowledge is successful, an error otherwise
 */
DPS_Status DPS_AckPublicationBufs(const DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                                  DPS_AckPublicationBufsComplete cb, void* data);

/**
 * Get the key identifier of an acknowledgement, only valid with the
 * body of the DPS_AcknowledgementHandler function.
 *
 * @param pub   The pub parameter of DPS_AcknowledgementHandler
 *
 * @return The key identifier of the subscriber, may be NULL
 */
const DPS_KeyId* DPS_AckGetSenderKeyId(const DPS_Publication* pub);

/** @} */ /* end of publication group */

/**
 * @defgroup subscription Subscription
 * Subscriptions.
 * @{
 */

/**
 * Opaque type for a subscription.
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
 *
 * @param sub   The subscription
 *
 * @return The number of topics.
 */
size_t DPS_SubscriptionGetNumTopics(const DPS_Subscription* sub);

/**
 * Allocate memory for a subscription and initialize topics
 *
 * @param node         The local node to use
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match - must be >= 1
 *
 * @return The newly created subscription or NULL if resources
 *         could not be allocated or the arguments were invalid
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
 * @return A pointer to the data or NULL if the subscription is invalid
 */
void* DPS_GetSubscriptionData(DPS_Subscription* sub);

/**
 * Get the local node associated with a subscription
 *
 * @param sub   The subscription
 *
 * @return The node or NULL if the subscription is invalid
 */
DPS_Node* DPS_SubscriptionGetNode(const DPS_Subscription* sub);

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
 * Start subscribing to a set of topics
 *
 * @param sub          The subscription to start
 * @param handler      Callback function to be called with topic matches
 *
 * @return DPS_OK if start is successful, an error otherwise
 */
DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler);

/**
 * Stop subscribing to the subscription topic and free resources allocated for the subscription
 *
 * @param sub   The subscription to cancel
 *
 * @return DPS_OK if destroy is successful, an error otherwise
 */
DPS_Status DPS_DestroySubscription(DPS_Subscription* sub);

/** @} */ /* end of subscription group */

#ifdef __cplusplus
}
#endif

#endif
