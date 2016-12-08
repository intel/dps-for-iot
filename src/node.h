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

#include <dps/private/network.h>
#include <uv.h>
#include "bitvec.h"
#include "history.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DPS message types
 */
#define DPS_MSG_TYPE_PUB  1
#define DPS_MSG_TYPE_SUB  2
#define DPS_MSG_TYPE_ACK  3

typedef struct _RemoteNode RemoteNode;

typedef struct _PublicationAck PublicationAck;

typedef struct _OnOpCompletion OnOpCompletion;

typedef struct _DPS_Node {
    void* userData;

    uint16_t tasks;                        /* Background tasks that have been scheduled */
    uint16_t port;
    char separators[13];                  /* List of separator characters */

    uv_thread_t thread;                   /* Thread for the event loop */
    uv_loop_t* loop;                      /* uv lib event loop */
    uv_mutex_t nodeMutex;                 /* Mutex to protect this node */
    uv_mutex_t condMutex;                 /* Mutex for use wih condition variables */
#ifndef NDEBUG
    int lockCount;                        /* Detect recursive locks */
#endif
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

    uint8_t stopped;                      /* True if the node is no longer running */
    DPS_OnNodeDestroyed onDestroyed;      /* Function to call when the node is destroyed */
    void* onDestroyedData;                /* Context to pass to onDestroyed callback */

} DPS_Node;

typedef struct _RemoteNode {
    OnOpCompletion* completion;
    uint8_t linked;                    /* True if this is a node that was explicitly linked */
    struct {
        uint8_t sync;                  /* If TRUE request remote to synchronize interests */
        uint8_t updates;               /* TRUE if updates have been received but not acted on */
        DPS_BitVector* needs;          /* Bit vector of needs received from  this remote node */
        DPS_BitVector* interests;      /* Bit vector of interests received from  this remote node */
    } inbound;
    struct {
        uint8_t sync;                  /* If TRUE synchronize outbound interests with remote node (no deltas) */
        uint8_t checkForUpdates;       /* TRUE if there may be updated interests to send to this remote */
        DPS_BitVector* needs;          /* Needs bit vector sent outbound to this remote node */
        DPS_BitVector* interests;      /* Interests bit vector sent outbound to this remote node */
    } outbound;
    DPS_NetEndpoint ep;
    uint64_t expires;
    /*
     * Remote nodes are doubly linked into a ring
     */
    struct _RemoteNode* prev;
    struct _RemoteNode* next;
} RemoteNode;

/*
 * If we have not heard anything from a remote node within the
 * keep alive time period it may be deleted. The keep alive
 * time is specified in seconds.
 */
#define DPS_REMOTE_NODE_KEEPALIVE  360

/*
 * Request to asynchronously updates subscriptions
 *
 * @param node    The node
 * @param remote  Remote node to check for updates or if NULL all remote nodes are checked
 */
int DPS_UpdateSubs(DPS_Node* node, RemoteNode* remote);

/*
 * Queue an acknowledgment to be sent asynchronously
 *
 * @param node    The node
 * @param ack     The acknowledgment to queue
 */
void DPS_QueuePublicationAck(DPS_Node* node, PublicationAck* ack);

/*
 * Callback function called when a network send operation completes
 */
void DPS_OnSendComplete(DPS_Node* node, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_Status status);

/*
 * Function to call when a network send operation fails. Must be called with the node lock held.
 */
void DPS_SendFailed(DPS_Node* node, DPS_NodeAddress* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status);

/*
 *
 */
DPS_Status DPS_AddRemoteNode(DPS_Node* node, DPS_NodeAddress* addr, DPS_NetConnection* cn, uint16_t ttl, RemoteNode** remoteOut);

/*
 *
 */
RemoteNode* DPS_DeleteRemoteNode(DPS_Node* node, RemoteNode* remote);

/*
 *
 */
void DPS_RemoteCompletion(DPS_Node* node, RemoteNode* remote, DPS_Status status);

/*
 * Lock the node
 *
 * @param The node to lock
 */
void DPS_LockNode(DPS_Node* node);

/*
 * Unlock the node
 *
 * @param The node to unlock
 */
void DPS_UnlockNode(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif

