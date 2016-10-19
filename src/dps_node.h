#ifndef _DPS_NODE_H
#define _DPS_NODE_H

#include <dps/bitvec.h>
#include <dps/dps_history.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _RemoteNode RemoteNode;

typedef struct _PublicationAck PublicationAck;

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

#ifdef __cplusplus
}
#endif

#endif

