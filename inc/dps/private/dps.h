/**
 * @file
 * Internal APIs
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

#ifndef _DPS_INTERNAL_H
#define _DPS_INTERNAL_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0])) /**< Helper macro to compute array size */

/**
 * Maximum number of application buffers when using DPS_PublishBufs()
 * and friends
 */
#define DPS_BUFS_MAX 16

/*
 * Map keys for CBOR serialization of DPS messages
 */
#define DPS_CBOR_KEY_PORT           1   /**< uint */
#define DPS_CBOR_KEY_TTL            2   /**< int */
#define DPS_CBOR_KEY_PUB_ID         3   /**< bstr (UUID) */
#define DPS_CBOR_KEY_SEQ_NUM        4   /**< uint */
#define DPS_CBOR_KEY_ACK_REQ        5   /**< bool */
#define DPS_CBOR_KEY_BLOOM_FILTER   6   /**< bstr */
#define DPS_CBOR_KEY_SUB_FLAGS      7   /**< uint */
#define DPS_CBOR_KEY_MESH_ID        8   /**< bstr (UUID) */
#define DPS_CBOR_KEY_NEEDS          9   /**< bstr */
#define DPS_CBOR_KEY_INTERESTS     10   /**< bstr */
#define DPS_CBOR_KEY_TOPICS        11   /**< array (tstr) */
#define DPS_CBOR_KEY_DATA          12   /**< bstr */
#define DPS_CBOR_KEY_ACK_SEQ_NUM   13   /**< uint */
#define DPS_CBOR_KEY_PATH          14   /**< tstr */

/**
 * Convert seconds to milliseconds
 */
#define DPS_SECS_TO_MS(t)   ((uint64_t)(t) * 1000ull)

/**
 * Maximum length of address text is of the form: "[IPv6%IFNAME]:PORT"
 */
#define DPS_NODE_ADDRESS_MAX_STRING_LEN (1 + INET6_ADDRSTRLEN + 1 + UV_IF_NAMESIZE + 2 + 8)

/**
 * Address types
 *
 * These correspond to the supported transports.
 */
typedef enum {
    DPS_UNKNOWN = 0,            /**< Unknown type */
    DPS_DTLS,                   /**< DTLS */
    DPS_TCP,                    /**< TCP */
    DPS_UDP,                    /**< UDP */
    DPS_PIPE,                   /**< Named pipe */
} DPS_NodeAddressType;

#ifdef _WIN32
#define DPS_NODE_ADDRESS_PATH_MAX 256 /**< Maximum pipe name length */
#else
#define DPS_NODE_ADDRESS_PATH_MAX 108 /**< Maximum pipe name length */
#endif

/**
 * Address type
 */
typedef struct _DPS_NodeAddress {
    DPS_NodeAddressType type;      /**< Type of address */
    union {
        struct sockaddr_storage inaddr; /**< Storage for IP address type */
        char path[DPS_NODE_ADDRESS_PATH_MAX]; /**< Storage for pipe name */
    } u; /**< Type specific storage */
} DPS_NodeAddress;

/**
 * Get the loopback address of the node's listening address.
 *
 * @param addr The loopback address
 * @param node The node
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status DPS_GetLoopbackAddress(DPS_NodeAddress* addr, DPS_Node* node);

/**
 * For managing data that has been received
 */
typedef struct _DPS_RxBuffer {
    uint8_t* base;   /**< base address for buffer */
    uint8_t* eod;    /**< end of data */
    uint8_t* rxPos;  /**< current read location in buffer */
} DPS_RxBuffer;

/**
 * Initialize a receive buffer
 *
 * @param buffer    Buffer to initialized
 * @param storage   The storage for the buffer. The storage cannot be NULL
 * @param size      The size of the storage
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if storage is needed and could not be allocated.
 */
DPS_Status DPS_RxBufferInit(DPS_RxBuffer* buffer, uint8_t* storage, size_t size);

/**
 * Free resources allocated for a buffer and nul out the buffer pointers.
 *
 * @param buffer    Buffer to free
 */
void DPS_RxBufferFree(DPS_RxBuffer* buffer);

/**
 * Clear receive buffer fields
 */
#define DPS_RxBufferClear(b) do { (b)->base = (b)->rxPos = (b)->eod = NULL; } while (0)

/**
 * Data available in a receive buffer
 */
#define DPS_RxBufferAvail(b)  ((uint32_t)((b)->eod - (b)->rxPos))

/**
 * For managing data to be transmitted
 */
typedef struct _DPS_TxBuffer {
    uint8_t* base;  /**< base address for buffer */
    uint8_t* eob;   /**< end of buffer */
    uint8_t* txPos; /**< current write location in buffer */
} DPS_TxBuffer;

/**
 * Initialize a transmit buffer
 *
 * @param buffer    Buffer to initialized
 * @param storage   The storage for the buffer. If the storage is NULL storage is allocated.
 * @param size      Current size of the buffer
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if storage is needed and could not be allocated.
 */
DPS_Status DPS_TxBufferInit(DPS_TxBuffer* buffer, uint8_t* storage, size_t size);

/**
 * Free resources allocated for a buffer and nul out the buffer pointers.
 *
 * @param buffer    Buffer to free
 */
void DPS_TxBufferFree(DPS_TxBuffer* buffer);

/**
 * Add data to a transmit buffer
 *
 * @param buffer   Buffer to append to
 * @param data     The data to append
 * @param len      Length of the data to append
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if there not enough room in the buffer
 */
DPS_Status DPS_TxBufferAppend(DPS_TxBuffer* buffer, const uint8_t* data, size_t len);

/**
 * Clear transmit buffer fields
 */
#define DPS_TxBufferClear(b) do { (b)->base = (b)->txPos = (b)->eob = NULL; } while (0)

/**
 * Space left in a transmit buffer
 */
#define DPS_TxBufferSpace(b)  ((uint32_t)((b)->eob - (b)->txPos))

/**
 * Number of bytes that have been written to a transmit buffer
 */
#define DPS_TxBufferUsed(b)  ((uint32_t)((b)->txPos - (b)->base))

/**
 * Size of transmit buffer
 */
#define DPS_TxBufferCapacity(b)  ((uint32_t)((b)->eob - (b)->base))

/**
 * Convert a transmit buffer into a receive buffer. Note that this
 * aliases the internal storage so care must be taken to avoid a
 * double free.
 *
 * @param txBuffer   A buffer containing data
 * @param rxBuffer   Receive buffer struct to be initialized
 */
void DPS_TxBufferToRx(const DPS_TxBuffer* txBuffer, DPS_RxBuffer* rxBuffer);

/**
 * Convert a receive buffer into a transmit buffer. Note that this
 * aliases the internal storage so care must be taken to avoid a
 * double free.
 *
 * @param rxBuffer   A buffer containing data
 * @param txBuffer   Transmit buffer struct to be initialized
 */
void DPS_RxBufferToTx(const DPS_RxBuffer* rxBuffer, DPS_TxBuffer* txBuffer);

/**
 * Print the current subscriptions
 *
 * @param node The node
 */
void DPS_DumpSubscriptions(DPS_Node* node);

/**
 * Copy a DPS_KeyId
 *
 * @param dest The key ID to copy to
 * @param src  The key ID to copy from
 *
 * @return dest on success or NULL on failure
 */
DPS_KeyId* DPS_CopyKeyId(DPS_KeyId* dest, const DPS_KeyId* src);

/**
 * Release memory used by the key ID.
 *
 * @param keyId The key ID
 */
void DPS_ClearKeyId(DPS_KeyId* keyId);

/**
 * A key store request.
 */
struct _DPS_KeyStoreRequest {
    DPS_KeyStore* keyStore; /**< The key store this request is directed to */
    void* data; /**< The caller provided request data */
    /** Called to provide a key and key identifier to the requestor */
    DPS_Status (*setKeyAndId)(DPS_KeyStoreRequest* request, const DPS_Key* key, const DPS_KeyId* keyId);
    /** Called to provide a key to the requestor */
    DPS_Status (*setKey)(DPS_KeyStoreRequest* request, const DPS_Key* key);
    /** Called to provide the CA chain to the requestor */
    DPS_Status (*setCA)(DPS_KeyStoreRequest* request, const char* ca);
    /** Called to provide a certificate to the requestor */
    DPS_Status (*setCert)(DPS_KeyStoreRequest* request, const char* cert, size_t certLen,
                          const char* key, size_t keyLen, const char* pwd, size_t pwdLen);
};

/**
 * A key store.
 */
struct _DPS_KeyStore {
    void* userData; /**< The application provided user data */
    DPS_KeyAndIdHandler keyAndIdHandler; /**< Called when a key and key identifier is requested */
    DPS_KeyHandler keyHandler; /**< Called when a key is requested */
    DPS_EphemeralKeyHandler ephemeralKeyHandler; /**< Called when an ephemeral key is requested */
    DPS_CAHandler caHandler; /**< Called when a CA chain is requested */
};

/**
 * Returns a non-secure random number
 *
 * @return a non-secure random number
 */
uint32_t DPS_Rand(void);

/**
 * Returns if publication is encrypted.
 *
 * @param pub The publication
 *
 * @return DPS_TRUE if encrypted, DPS_FALSE otherwise
 */
int DPS_PublicationIsEncrypted(const DPS_Publication* pub);

/** @copydoc DPS_NetRxBuffer */
typedef struct _DPS_NetRxBuffer DPS_NetRxBuffer;

/**
 * Inside a DPS_PublicationHandler, call this to receive the
 * underlying buffer that the payload is in.
 *
 * @param pub The publication
 *
 * @return the DPS_NetRxBuffer
 */
DPS_NetRxBuffer* DPS_PublicationGetNetRxBuffer(const DPS_Publication* pub);

#ifdef __cplusplus
}
#endif

#endif
