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

#ifndef _DPS_NODE_H
#define _DPS_NODE_H

#include <safe_lib.h>
#include <dps/private/network.h>
#include <uv.h>
#include "bitvec.h"
#include "cose.h"
#include "history.h"

#if UV_VERSION_MAJOR < 1 || UV_VERSION_MINOR < 7
#error libuv version 1.7 or higher is required
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DPS message types
 */
#define DPS_MSG_TYPE_PUB  1
#define DPS_MSG_TYPE_SUB  2
#define DPS_MSG_TYPE_ACK  3

#define DPS_NODE_CREATED      0
#define DPS_NODE_RUNNING      1
#define DPS_NODE_STOPPING     2
#define DPS_NODE_STOPPED      3

typedef struct _RemoteNode RemoteNode;

typedef struct _PublicationAck PublicationAck;

typedef struct _OnOpCompletion OnOpCompletion;

typedef struct _LinkMonitor LinkMonitor;

/*
 * Link monitor configuration values. All times are in milliseconds.
 */
typedef struct _LinkMonitorConfig {
    uint16_t retries;  /* Number of probe retries after a timeout */
    uint16_t retryTO;  /* Probe retry time */
    uint32_t probeTO;  /* Probe repeat time */
} LinkMonitorConfig;

typedef struct _DPS_Node {
    void* userData;

    uint8_t isSecured;                    /* Indicates if this node is secured */
    uint8_t lockCount;                    /* Recursive lock counter */
    uint16_t tasks;                       /* Background tasks that have been scheduled */
    uint16_t port;
    DPS_UUID meshId;                      /* Randomly allocated mesh id for this node */
    DPS_UUID minMeshId;                   /* Minimum mesh id seen by this node */
    char separators[13];                  /* List of separator characters */
    DPS_KeyStore *keyStore;               /* Functions for loading encryption keys */
    DPS_UUID keyId;                       /* Encryption key identifier */

    uv_thread_t lockHolder;               /* Thread currently holding the node lock */
    uv_thread_t thread;                   /* Thread for the event loop */
    uv_loop_t* loop;                      /* uv lib event loop */
    uv_mutex_t nodeMutex;                 /* Mutex to protect this node */
    uv_mutex_t condMutex;                 /* Mutex for use wih condition variables */
    uv_async_t bgHandler;                 /* Async handler for background tasks */

    struct {
        PublicationAck* first;
        PublicationAck* last;
    } ackQueue;                           /* Queued acknowledgment packets */

    RemoteNode* remoteNodes;              /* Linked list of remote nodes */

    struct {
        DPS_BitVector* needs;             /* Preallocated needs bit vector */
        DPS_BitVector* interests;         /* Preallocated interests bit vector */
    } scratch;

    DPS_CountVector* interests;           /* Tracks all interests for this node */
    DPS_CountVector* needs;               /* Tracks all needs for this node */

    DPS_History history;                  /* History of recently sent publications */

    DPS_Publication* publications;        /* Linked list of local and retained publications */
    DPS_Subscription* subscriptions;      /* Linked list of local subscriptions */

    DPS_MulticastReceiver* mcastReceiver;
    DPS_MulticastSender* mcastSender;

    DPS_NetContext* netCtx;               /* Network context */

    uint8_t state;                        /* Indicates if the node is running, stopping, or stopped */
    DPS_OnNodeDestroyed onDestroyed;      /* Function to call when the node is destroyed */
    void* onDestroyedData;                /* Context to pass to onDestroyed callback */

    LinkMonitorConfig linkMonitorConfig;  /* Configuration parameters for mesh probe publications */

} DPS_Node;

extern const DPS_UUID DPS_MaxMeshId;

#define DPS_SUB_FLAG_SYNC_INF    1      /* Inform remote interests are being synched (not delta) */
#define DPS_SUB_FLAG_SYNC_REQ    2      /* Request remote to send synched interests */
#define DPS_SUB_FLAG_MUTE_INF    4      /* Inform remote node sender is muted */

typedef struct _RemoteNode {
    OnOpCompletion* completion;
    uint8_t linked;                    /* TRUE if this is a node that was explicitly linked */
    uint8_t unlink;                    /* TRUE if this node is about to be unlinked */
    struct {
        uint8_t muted;                 /* TRUE if the remote informed us the that link is muted */
        uint8_t sync;                  /* If TRUE request remote to synchronize interests */
        uint32_t sequenceNum;          /* Sequence number of last subscription received from this node */
        DPS_UUID meshId;               /* The mesh id received from this remote node */
        DPS_BitVector* needs;          /* Bit vector of needs received from  this remote node */
        DPS_BitVector* interests;      /* Bit vector of interests received from  this remote node */
    } inbound;
    struct {
        uint8_t muted;                 /* TRUE if we have informed the remote that the link is muted */
        uint8_t sync;                  /* If TRUE synchronize outbound interests with remote node (no deltas) */
        uint8_t checkForUpdates;       /* TRUE if there may be updated interests to send to this remote */
        uint32_t sequenceNum;          /* Sequence number of last subscription sent to this node */
        DPS_UUID meshId;               /* The mesh id sent to this remote node */
        DPS_BitVector* needs;          /* Needs bit vector sent outbound to this remote node */
        DPS_BitVector* interests;      /* Interests bit vector sent outbound to this remote node */
    } outbound;
    LinkMonitor* monitor;              /* For monitoring muted links */
    DPS_NetEndpoint ep;
    RemoteNode* next;                  /* Remotes are a linked list attached to the local node */
} RemoteNode;

/**
 * Request to asynchronously updates subscriptions
 *
 * @param node    The node
 * @param remote  Remote node to check for updates or if NULL all remote nodes are checked
 */
int DPS_UpdateSubs(DPS_Node* node, RemoteNode* remote);

/**
 * Queue an acknowledgment to be sent asynchronously
 *
 * @param node    The node
 * @param ack     The acknowledgment to queue
 */
void DPS_QueuePublicationAck(DPS_Node* node, PublicationAck* ack);

/**
 * Callback function called when a network send operation completes
 *
 * @param node    The node
 */
void DPS_OnSendComplete(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status);

/*
 * Make a nonce for a specific message type
 */
void DPS_MakeNonce(const DPS_UUID* uuid, uint32_t seqNum, uint8_t msgType, uint8_t nonce[DPS_COSE_NONCE_SIZE]);

/**
 * Function to call when a network send operation fails. Must be called with the node lock held.
 *
 * @param node    The local node
 */
void DPS_SendFailed(DPS_Node* node, DPS_NodeAddress* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status);

/**
 * Add an entry for new remote node or return a pointer to the existing remote node.
 *
 * @param node      The local node
 * @param addr      The address of the remote node
 * @param cn        Connection state information for the node
 * @param remoteOut Returns an existing or new remote node structure
 *
 * @return
 *          - DPS_OK if a new remote node was added
 *          - DPS_ERR_EXISTS if the node already exists
 *          - Other status codes indicating an error
 */
DPS_Status DPS_AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, DPS_NetConnection* cn, RemoteNode** remoteOut);

/**
 * Lookup a remote node by address.
 *
 * Must be called with the node lock held.
 *
 * @param node    The local node
 * @param addr    The address of the remote node to lookup
 *
 * @return  A pointer to the remote node or NULL if the lookup failed.
 */
RemoteNode* DPS_LookupRemoteNode(DPS_Node* node, DPS_NodeAddress* addr);

/**
 * Must be called with the node lock held.
 *
 * @param node    The local node
 * @param src     The remote that just sent a subscription
 * @param meshId  The mesh id in the subscription
 */
int DPS_MeshHasLoop(DPS_Node* node, RemoteNode* src, DPS_UUID* meshId);

/**
 * Deletes a remote node and related state information.
 *
 * @param node    The local node
 * @param remote  The remote node to delete
 */
RemoteNode* DPS_DeleteRemoteNode(DPS_Node* node, RemoteNode* remote);

/**
 * Complete an asychronous operation on a remote node
 *
 * @param node    The local node
 * @param remote  The remote node to complete
 * @param status  Status code indicating the success or failure of the operation
 */
void DPS_RemoteCompletion(DPS_Node* node, RemoteNode* remote, DPS_Status status);

/**
 * Mute a remote node. Remote nodes are muted we detect a
 * loop in the mesh.
 *
 * @param node    The local node
 * @param remote  The remote node to mute
 */
DPS_Status DPS_MuteRemoteNode(DPS_Node* node, RemoteNode* remote);

/**
 * Unmute a remote node
 *
 * @param node    The local node
 * @param remote  The remote node to unmute
 */
DPS_Status DPS_UnmuteRemoteNode(DPS_Node* node, RemoteNode* remote);

/**
 * Clears the inbound interests and needs for a remote node
 * including all the count vector bookkeeping.
 *
 * @param node    The local node
 * @param remote  The remote node to clear
 */
void DPS_ClearInboundInterests(DPS_Node* node, RemoteNode* remote);

/**
 * Lock the node
 *
 * @param node The node to lock
 */
void DPS_LockNode(DPS_Node* node);

/**
 * Unlock the node
 *
 * @param node The node to unlock
 */
void DPS_UnlockNode(DPS_Node* node);

/**
 * Check if the current thread is holding the node lock.
 * This is intended for use in asserts.
 *
 * @param node The node to check
 */
int DPS_HasNodeLock(DPS_Node* node);

/**
 * Generates a random UUID that is less than the UUID passed in.
 * Less in this context means DPS_UUIDCompare(&new, old) < 0
 *
 * @param uuid  The UUID to be updated.
 */
void DPS_RandUUIDLess(DPS_UUID* uuid);

/**
 * For debug output of mesh ids
 */
#define UUID_32(n) (((n)->val[0] << 24) | ((n)->val[1] << 16) | ((n)->val[2] << 8) | ((n)->val[3] << 0))

#ifdef __cplusplus
}
#endif

#endif

