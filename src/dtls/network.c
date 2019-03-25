/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <safe_lib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "../mbedtls.h"
#include "../node.h"
#include "../queue.h"

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_cookie.h"

/*
 * NOTES
 *
 * Before communicating data, DTLS needs to perform a handshake with
 * the peer. During this phase DTLS needs retransmission and ordering
 * of messages. Besides data and handshake packets, there are also
 * packets containing "events" like notification that a peer is going
 * to close.
 *
 * mbedtls doesn't talk directly to the network, instead it expects
 * client code to trigger it's execution once network data is
 * available, then uses a callback to read the actual data. Other
 * actions are also implemented with callbacks.
 */

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Controls debug output from the mbedtls library, ranges from 0 (no
 * debug) to 4 (verbose).
 */
#define DEBUG_MBEDTLS_LEVEL 1

/* Personalization string for the DRBG */
#define PERSONALIZATION_STRING "DPS_DRBG"

typedef struct _RecvData {
    DPS_Queue queue;
    uv_buf_t buf;
} RecvData;

typedef struct _SendRequest {
    DPS_Queue queue;
    DPS_NetConnection* cn;
    void* appCtx;
    uv_buf_t* bufs;
    size_t numBufs;

    DPS_Status status;
    DPS_NetSendComplete sendCompleteCB;
} SendRequest;

/*
 * DPS_NetConnection holds mbedtls supporting data and any pending
 * reads and writes. These pending structures are used for buffering
 * during handshake phase, but also to solve some memory lifecycle
 * issues -- ensuring certain buffers are alive for enough time.
 */
typedef struct _DPS_NetConnection {
    DPS_NetContext* netCtx;
    DPS_Node* node;
    /*
     * The ref counting strategy is as follows:
     * - Creating a client connection adds a ref that the caller owns,
     * - Each pending write or read owns a ref,
     * - Each callback with user data of a connection owns a ref,
     * - Refs are used to protect the connection from being destroyed
     *   during calls to mbedtls that issue callbacks that affect the
     *   above.
     * Lastly, there are some shenanigans around resetting connections
     * and waiting for the first message from incoming connections.
     */
    int refCount;

    /*
     * Socket of client connections, server connections reuse
     * netCtx->rxSocket.
     */
    uv_udp_t socket;

    /*
     * Peer as seen by upper layers - the upper layers rewrite the
     * peer port from the DPS messages
     */
    DPS_NetEndpoint peer;
    /* Peer address as seen by this layer */
    DPS_NodeAddress* peerAddr;

    /*
     * mbedtls uses different logic for client and server, so keep
     * track of the role in a connection.
     */
    int type;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;

    int handshakeDone;
    int handshake;

    enum {
          CN_OPEN = 0,
          CN_CLOSE_NOTIFIED = 1,
          CN_CLOSING = 2
    } state;

    /*
     * Entries in the receive queue are created from data received from
     * the network, and consumed by the callback we give to mbedtls.
     */
    DPS_Queue recvQueue;

    /*
     * Entries in the send queue are created with data we want to
     * send to the network (via DPS_NetSend), and consumed when asking
     * mbedtls to encrypt data.
     */
    DPS_Queue sendQueue;

    /*
     * When entries from send queue are consumed, move them to
     * callback queue so that the callback is called later, in an
     * idler without any locks.
     */
    uv_idle_t idleForSendCallbacks;
    DPS_Queue sendCompletedQueue;

    /*
     * Keep track of current timeout state for DTLS. mbedtls calls
     * back to set and peek at timer state, but it is up to us call
     * mbedtls when timer triggers.
     */
    uv_timer_t timer;
    int timerStatus;

    /* For server connection. */
    mbedtls_ssl_cookie_ctx cookieCtx;
    mbedtls_ssl_cache_context cacheCtx;

    DPS_NetConnection* next;
} DPS_NetConnection;

#define MAX_READ_LEN   65536

#define NET_RUNNING  1          /**< Net layer is running */
#define NET_STOPPING 2          /**< Net layer is stopping */

struct _DPS_NetContext {
    int state;
    uv_udp_t rxSocket;
    uv_udp_recv_cb dataCB;
    uint32_t handshakeTimeoutMin;
    uint32_t handshakeTimeoutMax;
    DPS_Node* node;
    DPS_OnReceive receiveCB;
    DPS_NetConnection* cns;
};

/*
 * Used when the key store supports certificates.
 */
static const int AllCipherSuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
};

/*
 * Used when the key store supports only PSKs.
 */
static const int PskCipherSuites[] = {
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
};

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    buf->base = calloc(MAX_READ_LEN, sizeof(uint8_t));
    if (buf->base) {
        buf->len = MAX_READ_LEN;
    } else {
        buf->len = 0;
    }
}

static void OnServerData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_NetContext* netCtx = socket->data;
    netCtx->dataCB(socket, nread, buf, addr, flags);
}

static void OnClientData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_NetConnection* cn = socket->data;
    DPS_NetContext* netCtx = cn->netCtx;
    /*
     * Use the rxSocket here as it's only purpose in dataCB is to get
     * to the DPS_NetContext
     */
    netCtx->dataCB(&netCtx->rxSocket, nread, buf, addr, flags);
}

static uv_udp_t* GetSocket(DPS_NetConnection* cn)
{
    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        DPS_NetContext* netCtx = cn->netCtx;
        return &netCtx->rxSocket;
    } else {
        return &cn->socket;
    }
}

static DPS_NetConnection* LookupConnection(DPS_NetContext* netCtx, DPS_NodeAddress* addr)
{
    DPS_NetConnection* cn;

    for (cn = netCtx->cns; cn != NULL; cn = cn->next) {
        if (DPS_SameAddr(cn->peerAddr, addr)) {
            return cn;
        }
    }
    return NULL;
}

static RecvData* CreateRecvData(ssize_t nread, const uv_buf_t* buf)
{
    RecvData* data;

    data = calloc(1, sizeof(RecvData));
    if (!data) {
        return NULL;
    }
    /* buf was allocated already via AllocBuffer. */
    data->buf = *buf;
#ifdef _WIN32
    data->buf.len = (ULONG) nread;
#else
    data->buf.len = nread;
#endif
    return data;
}

static void DestroyRecvData(RecvData* data)
{
    if (data) {
        if (data->buf.base) {
            free(data->buf.base);
        }
        free(data);
    }
}

static SendRequest* CreateSendRequest(void* appCtx, uv_buf_t* bufs, size_t numBufs,
                                        DPS_NetSendComplete sendCompleteCB)
{
    SendRequest* req;

    req = calloc(1, sizeof(SendRequest));
    if (!req) {
        return NULL;
    }
    req->appCtx = appCtx;
    req->bufs = calloc(numBufs, sizeof(uv_buf_t));
    if (!req->bufs) {
        free(req);
        return NULL;
    }
    memcpy_s(req->bufs, numBufs * sizeof(uv_buf_t), bufs, numBufs * sizeof(uv_buf_t));
    req->numBufs = numBufs;
    req->sendCompleteCB = sendCompleteCB;
    return req;
}

static void DestroySendRequest(SendRequest* req)
{
    if (req) {
        if (req->bufs) {
            free(req->bufs);
        }
        free(req);
    }
}

static void CancelPending(DPS_NetConnection* cn)
{
    /*
     * Protect connection while we are modifying the queues.
     */
    DPS_NetConnectionIncRef(cn);

    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
        DPS_QueueRemove(&req->queue);
        DPS_DBGPRINT("Canceling SendRequest=%p\n", req);
        req->status = DPS_ERR_NETWORK;
        DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    }
    while (!DPS_QueueEmpty(&cn->sendCompletedQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendCompletedQueue);
        DPS_QueueRemove(&req->queue);
        req->sendCompleteCB(cn->node, req->appCtx, &cn->peer, req->bufs, req->numBufs, req->status);
        DPS_NetConnectionDecRef(cn);
        DestroySendRequest(req);
    }

    DPS_NetConnectionDecRef(cn);
}

static void OnTLSDebug(void *ctx, int level, const char *file, int line, const char *str)
{
    static const DPS_LogLevel levels[] = {
        0,                  /* No debug */
        DPS_LOG_ERROR,      /* Error */
        DPS_LOG_DBGPRINT,   /* State change */
        DPS_LOG_DBGPRINT,   /* Informational */
        DPS_LOG_DBGTRACE    /* Verbose */
    };
    switch (level) {
    case 1:
        DPS_Log(DPS_LOG_WARNING, file, line, NULL, "%s", str);
        break;
    case 2:
    case 3:
    case 4:
        if (DPS_DEBUG_ENABLED()) {
            DPS_Log(levels[level], file, line, NULL, "%s", str);
        }
        break;
    }
}

static void DestroyConnection(DPS_NetConnection* cn);
static int TLSHandshake(DPS_NetConnection* cn);
static void ConsumePending(DPS_NetConnection* cn);

/*
 * PSK
 */

static DPS_Status TLSPSKSet(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_ssl_set_hs_psk(&cn->ssl, key->symmetric.key, key->symmetric.len);
    if (ret != 0) {
        DPS_ERRPRINT("Set PSK failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static int OnTLSPSKGet(void *data, mbedtls_ssl_context* ssl, const uint8_t* id, size_t idLen)
{
    DPS_NetConnection* cn = data;
    DPS_KeyStore* keyStore = cn->node->keyStore;
    DPS_KeyId keyId = { id, idLen };
    DPS_KeyStoreRequest request;
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!keyStore || !keyStore->keyHandler) {
        DPS_ERRPRINT("Missing key store for PSK\n");
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    memset(&request, 0, sizeof(request));
    request.keyStore = keyStore;
    request.data = cn;
    request.setKey = TLSPSKSet;
    ret = keyStore->keyHandler(&request, &keyId);
    if (ret != DPS_OK) {
        DPS_WARNPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    return 0;
}

/*
 * TIMER
 *
 * During handshake mbedtls keep track whether it needs to resend
 * packets. This is done by using two callbacks OnTLSTimerSet() and
 * OnTLSTimerGet() used to set and peek at the timeout values for a
 * given connection. It is responsibility of our code to trigger
 * mbedtls if the timeout has passed.
 */

static void OnTimeout(uv_timer_t* timer)
{
    DPS_NetConnection* cn = timer->data;
    int ret;

    DPS_DBGTRACEA("cn=%p\n", cn);

    cn->timerStatus++;
    if (cn->timerStatus == 1) {
        DPS_DBGPRINT("intermediate DTLS timeout\n");
    } else if (cn->timerStatus == 2) {
        DPS_DBGPRINT("final DTLS timeout\n");
        uv_timer_stop(&cn->timer);
        /*
         * Timeout is only used for retransmissions during handshake,
         * so when we reach the final timeout, trigger mbedtls to
         * perform a handshake step.
         */
        ret = TLSHandshake(cn);
        if (ret == DPS_TRUE && cn->handshakeDone) {
            ConsumePending(cn);
        } else if (ret == DPS_FALSE) {
            CancelPending(cn);
        }
        DPS_NetConnectionDecRef(cn);
    }
}

static void OnTLSTimerSet(void* data, uint32_t int_ms, uint32_t fin_ms)
{
    DPS_NetConnection* cn = data;

    DPS_DBGTRACEA("cn=%p,int_ms=%u,fin_ms=%u\n", cn, int_ms, fin_ms);

    int active = uv_is_active((uv_handle_t*)&cn->timer);

    if (fin_ms == 0) {
        cn->timerStatus = -1;
        if (active) {
            uv_timer_stop(&cn->timer);
            DPS_NetConnectionDecRef(cn);
        }
        return;
    }

    assert(int_ms < fin_ms);

    cn->timerStatus = 0;
    if (active) {
        uv_timer_stop(&cn->timer);
    }
    uv_timer_start(&cn->timer, OnTimeout, int_ms, fin_ms - int_ms);
    if (!active) {
        DPS_NetConnectionIncRef(cn);
    }
}

static int OnTLSTimerGet(void* data)
{
    DPS_NetConnection* cn = data;

    DPS_DBGTRACEA("cn=%p timerStatus=%d\n", cn, cn->timerStatus);

    return cn->timerStatus;
}

/*
 * DATA TRANSMISSION CALLBACKS
 *
 * mbedtls uses callbacks to read data from the network and to write
 * data for the network. Note that when our code gets new data from
 * the network, it needs to trigger mbedtls that will then callback to
 * read the data. Unfortunately mbedtls doesn't provide a way to
 * directly feed the data into its state machine.
 *
 * OnTLSRecv() consumes the receive queue. OnTLSSend uses uv_udp
 * functions to write to the network directly.
 */

static int OnTLSRecv(void* userData, unsigned char *buf, size_t len)
{
    DPS_NetConnection* cn = userData;
    RecvData* data;

    DPS_DBGTRACEA("cn=%p,buf=%p,len=%d\n", cn, buf, len);

    if (DPS_QueueEmpty(&cn->recvQueue)) {
        DPS_DBGPRINT("Receive queue empty\n");
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    data = (RecvData*)DPS_QueueFront(&cn->recvQueue);

    DPS_DBGPRINT("Using queued data with %zu bytes\n", data->buf.len);
    if (data->buf.len > len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    if (data->buf.len > INT_MAX) {
        /* data->buf.len will be truncated to an int return value */
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    size_t dataLen = data->buf.len;
    memcpy_s(buf, data->buf.len, data->buf.base, dataLen);

    DPS_QueueRemove(&data->queue);
    DPS_NetConnectionDecRef(cn);
    DestroyRecvData(data);
    return (int) dataLen;
}

typedef struct _SendReq {
    uv_udp_send_t uvReq;
    uv_buf_t buf;
    DPS_NetConnection* cn;
} SendReq;

static SendReq* CreateSendReq(DPS_NetConnection* cn, const unsigned char *buf, size_t len)
{
    SendReq* sendReq;

#ifdef _WIN32
    /* Windows, sendReq->buf.len is a ULONG, not a size_t */
    if (len > ULONG_MAX) {
        return NULL;
    }
#endif

    sendReq = calloc(1, sizeof(SendReq));
    if (!sendReq) {
        return NULL;
    }
    /*
     * We don't own the buffer mbedtls passed us, need to copy for the
     * UDP request that is async.
     */
    sendReq->buf.base = malloc(len);
    if (!sendReq->buf.base) {
        free(sendReq);
        return NULL;
    }
    memcpy_s(sendReq->buf.base, len, buf, len);
#ifdef _WIN32
    sendReq->buf.len = (ULONG) len;
#else
    sendReq->buf.len = len;
#endif
    sendReq->uvReq.data = sendReq;
    sendReq->cn = cn;
    return sendReq;
}

static void DestroySendReq(SendReq* sendReq)
{
    if (sendReq) {
        if (sendReq->buf.base) {
            free(sendReq->buf.base);
        }
        free(sendReq);
    }
}

static void OnSendComplete(uv_udp_send_t *req, int status)
{
    SendReq* sendReq = req->data;

    DPS_DBGTRACEA("sendReq=%p{cn=%p},status=%d\n", sendReq, sendReq->cn, status);

    if (status != 0) {
        DPS_ERRPRINT("Send failed: %s\n", uv_err_name(status));
    }
    DPS_NetConnectionDecRef(sendReq->cn);
    DestroySendReq(sendReq);
}

static int OnTLSSend(void* data, const unsigned char *buf, size_t len)
{
    DPS_NetConnection* cn = data;
    SendReq* sendReq = NULL;

    DPS_DBGTRACEA("cn=%p,buf=%p,len=%d\n", cn, buf, len);

    if (len > INT_MAX) {
        /* len will be truncated to an int return value */
        goto ErrorExit;
    }

    sendReq = CreateSendReq(cn, buf, len);
    if (!sendReq) {
        goto ErrorExit;
    }

    DPS_DBGPRINT("Created sendReq=%p\n", sendReq);

    struct sockaddr_storage inaddr;
    memcpy_s(&inaddr, sizeof(inaddr), &cn->peer.addr.u.inaddr, sizeof(cn->peer.addr.u.inaddr));
    DPS_MapAddrToV6((struct sockaddr *)&inaddr);

    int err = uv_udp_send(&sendReq->uvReq, GetSocket(cn), &sendReq->buf, 1,
                          (const struct sockaddr *)&inaddr, OnSendComplete);
    if (err) {
        DPS_ERRPRINT("Send failed: %s\n", uv_err_name(err));
        goto ErrorExit;
    }
    DPS_NetConnectionIncRef(cn);

    return (int) len;

 ErrorExit:
    DestroySendReq(sendReq);
    return -1;
}

static void RxHandleClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed Rx handle %p\n", handle);
    free(handle->data);
}

static void FreeConnection(DPS_NetConnection* cn)
{
    mbedtls_ssl_free(&cn->ssl);
    mbedtls_ssl_config_free(&cn->conf);
    mbedtls_pk_free(&cn->pkey);
    mbedtls_x509_crt_free(&cn->cacert);
    mbedtls_x509_crt_free(&cn->cert);
    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_cache_free(&cn->cacheCtx);
        mbedtls_ssl_cookie_free(&cn->cookieCtx);
    }
    mbedtls_ctr_drbg_free(&cn->drbg);
    mbedtls_entropy_free(&cn->entropy);

    if (cn->peerAddr) {
        DPS_DestroyAddress(cn->peerAddr);
    }

    if (cn->netCtx) {
        DPS_NetConnection* next = cn->next;
        if (cn->netCtx->cns == cn) {
            cn->netCtx->cns = next;
        } else if (cn->netCtx->cns) {
            DPS_NetConnection* prev = cn->netCtx->cns;
            while (prev->next != cn) {
                prev = prev->next;
                assert(prev);
            }
            prev->next = next;
        }
    }
    /*
     * DPS_NetStop may have been called while some connections are
     * still active.  Finish the work of DPS_NetStop here when the
     * last connection is removed from the list.
     */
    if ((cn->netCtx->state == NET_STOPPING) && !cn->netCtx->cns) {
        uv_udp_recv_stop(&cn->netCtx->rxSocket);
        uv_close((uv_handle_t*)&cn->netCtx->rxSocket, RxHandleClosed);
    }
    free(cn);
}

static void TimerClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    FreeConnection(cn);
}

static void IdleForCallbacksClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    if (!uv_is_closing((uv_handle_t*)&cn->timer)) {
        uv_close((uv_handle_t*)&cn->timer, TimerClosed);
    } else {
        FreeConnection(cn);
    }
}

static void SocketClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;

    if (!uv_is_closing((uv_handle_t*)&cn->idleForSendCallbacks)) {
        uv_close((uv_handle_t*)&cn->idleForSendCallbacks, IdleForCallbacksClosed);
    } else if (!uv_is_closing((uv_handle_t*)&cn->timer)) {
        uv_close((uv_handle_t*)&cn->timer, TimerClosed);
    } else {
        FreeConnection(cn);
    }
}

static void DestroyConnection(DPS_NetConnection* cn)
{
    DPS_DBGTRACEA("cn=%p\n", cn);

    assert(cn->refCount == 0);
    assert(DPS_QueueEmpty(&cn->recvQueue));
    assert(DPS_QueueEmpty(&cn->sendQueue));
    assert(DPS_QueueEmpty(&cn->sendCompletedQueue));
    assert(cn->handshake != MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED &&
           cn->handshake != MBEDTLS_ERR_SSL_WANT_READ &&
           cn->handshake != MBEDTLS_ERR_SSL_WANT_WRITE);

    switch (cn->state) {
    case CN_OPEN:
        cn->state = CN_CLOSE_NOTIFIED;
        int ret = mbedtls_ssl_close_notify(&cn->ssl);
        if (ret != 0) {
            DPS_ERRPRINT("Close notify failed: %s\n", TLSErrTxt(ret));
        }
        /*
         * The ref count may be non-0 now if mbedtls has work to do
         * for the close notify above.
         */
        if (cn->refCount > 0) {
            return;
        }
        /* FALLTHROUGH */
    case CN_CLOSE_NOTIFIED:
        cn->state = CN_CLOSING;
        assert(!uv_is_active((uv_handle_t*)&cn->timer));
        if (uv_is_active((uv_handle_t*)&cn->idleForSendCallbacks)) {
            uv_idle_stop(&cn->idleForSendCallbacks);
            DPS_NetConnectionDecRef(cn);
        }
        if (cn->type == MBEDTLS_SSL_IS_CLIENT) {
            uv_udp_recv_stop(&cn->socket);
        }
        if ((cn->type == MBEDTLS_SSL_IS_CLIENT) && !uv_is_closing((uv_handle_t*)&cn->socket)) {
            uv_close((uv_handle_t*)&cn->socket, SocketClosed);
        } else if (!uv_is_closing((uv_handle_t*)&cn->idleForSendCallbacks)) {
            uv_close((uv_handle_t*)&cn->idleForSendCallbacks, IdleForCallbacksClosed);
        } else if (!uv_is_closing((uv_handle_t*)&cn->timer)) {
            uv_close((uv_handle_t*)&cn->timer, TimerClosed);
        } else {
            FreeConnection(cn);
        }
        break;
    case CN_CLOSING:
        /*
         * A close callback is pending and will drive the rest of the
         * destroy steps.
         */
        return;
    }
}

static int ResetConnection(DPS_NetConnection* cn, const struct sockaddr* addr)
{
    char clientID[INET6_ADDRSTRLEN] = { 0 };
    int ret;

    /* Only called for servers with cookies enabled */
    assert(cn->type == MBEDTLS_SSL_IS_SERVER);

    ret = mbedtls_ssl_session_reset(&cn->ssl);
    if (ret) {
        DPS_ERRPRINT("Session reset failed: %s\n", TLSErrTxt(ret));
        goto Exit;
    }
    if (addr->sa_family == AF_INET) {
        ret = uv_ip4_name((const struct sockaddr_in*)addr, clientID, sizeof(clientID));
    } else {
        ret = uv_ip6_name((const struct sockaddr_in6*)addr, clientID, sizeof(clientID));
    }
    if (ret) {
        DPS_ERRPRINT("Convert addr to string failed: %s\n", uv_err_name(ret));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    ret = mbedtls_ssl_set_client_transport_id(&cn->ssl, (const unsigned char*)clientID, strnlen_s(clientID, sizeof(clientID)));
    if (ret) {
        DPS_ERRPRINT("Set client transport ID failed: %s\n", TLSErrTxt(ret));
    }

 Exit:
    return ret;
}

static DPS_Status SetCA(DPS_KeyStoreRequest* request, const char* ca)
{
    DPS_NetConnection* cn = request->data;
    size_t len;
    int ret;

    len = ca ? strnlen_s(ca, RSIZE_MAX_STR) + 1 : 0;
    if (len > RSIZE_MAX_STR) {
        DPS_ERRPRINT("Invalid CA\n");
        return DPS_ERR_MISSING;
    }
    ret = mbedtls_x509_crt_parse(&cn->cacert, (const unsigned char*)ca, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing trusted certificate(s) failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status SetCert(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    DPS_NetConnection* cn = request->data;
    size_t len;
    size_t pwLen;
    int ret;

    if (key->type != DPS_KEY_EC_CERT) {
        return DPS_ERR_MISSING;
    }
    len = key->cert.cert ? strnlen_s(key->cert.cert, RSIZE_MAX_STR) + 1 : 0;
    if (len > RSIZE_MAX_STR) {
        return DPS_ERR_MISSING;
    }
    ret = mbedtls_x509_crt_parse(&cn->cert, (const unsigned char*)key->cert.cert, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing certificate failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    len = key->cert.privateKey ? strnlen_s(key->cert.privateKey, RSIZE_MAX_STR) + 1 : 0;
    if (len > RSIZE_MAX_STR) {
        return DPS_ERR_MISSING;
    }
    pwLen = key->cert.password ? strnlen_s(key->cert.password, RSIZE_MAX_STR) : 0;
    if (pwLen == RSIZE_MAX_STR) {
        return DPS_ERR_MISSING;
    }
    ret =  mbedtls_pk_parse_key(&cn->pkey, (const unsigned char*)key->cert.privateKey, len,
                                (const unsigned char*)key->cert.password, pwLen);
    if (ret != 0) {
        DPS_WARNPRINT("Parse private key failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status SetKeyAndId(DPS_KeyStoreRequest* request, const DPS_Key* key,
                              const DPS_KeyId* keyId)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_ssl_conf_psk(&cn->conf, key->symmetric.key, key->symmetric.len, keyId->id, keyId->len);
    if (ret != 0) {
        DPS_WARNPRINT("Set PSK failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_NetConnection* CreateConnection(DPS_Node* node, const struct sockaddr* addr, int type)
{
    int ret;
    DPS_NetConnection* cn;
    DPS_NetContext* netCtx = node->netCtx;
    DPS_KeyStore* keyStore = node->keyStore;
    DPS_KeyStoreRequest request;
    const int* ciphersuites = AllCipherSuites;

    DPS_DBGTRACEA("node=%p,addr=%s,type=%s\n",
                  node, DPS_NetAddrText(addr), (type == MBEDTLS_SSL_IS_SERVER) ? "server" : "client");

    if (!keyStore) {
        DPS_ERRPRINT("Missing key store\n");
        return NULL;
    }

    cn = calloc(1, sizeof(DPS_NetConnection));
    if (!cn) {
        return NULL;
    }

    cn->netCtx = netCtx;
    cn->node = node;
    cn->type = type;
    cn->peerAddr = DPS_CreateAddress();
    DPS_NetSetAddr(cn->peerAddr, DPS_DTLS, addr);

    uv_timer_init(node->loop, &cn->timer);
    cn->timerStatus = -1;
    cn->timer.data = cn;

    DPS_QueueInit(&cn->recvQueue);
    DPS_QueueInit(&cn->sendQueue);
    DPS_QueueInit(&cn->sendCompletedQueue);
    uv_idle_init(node->loop, &cn->idleForSendCallbacks);
    cn->idleForSendCallbacks.data = cn;

    /*
     * Clients need a new socket so that concurrent connections can be
     * distinguished when packets are received.
     */
    if (type == MBEDTLS_SSL_IS_CLIENT) {
        struct sockaddr_storage addr;
        ret = uv_udp_init(node->loop, &cn->socket);
        if (ret) {
            DPS_ERRPRINT("UDP init failed: %s\n", uv_err_name(ret));
            goto ErrorExit;
        }
        cn->socket.data = cn;
        ret = uv_ip6_addr("::", 0, (struct sockaddr_in6*)&addr);
        if (ret) {
            goto ErrorExit;
        }
        ret = uv_udp_bind(&cn->socket, (const struct sockaddr*)&addr, 0);
        if (ret) {
            goto ErrorExit;
        }
        ret = uv_udp_recv_start(&cn->socket, AllocBuffer, OnClientData);
        if (ret) {
            DPS_ERRPRINT("UDP start failed: %s\n", uv_err_name(ret));
            goto ErrorExit;
        }
        {
            struct sockaddr_in6 addr;
            int len = sizeof(addr);
            if (uv_udp_getsockname(&cn->socket, (struct sockaddr*)&addr, &len) == 0) {
                DPS_DBGPRINT("Client port = %d\n", ntohs(addr.sin6_port));
            }
        }
    }

    mbedtls_entropy_init(&cn->entropy);

    /*
     * The default implementation is in
     * mbedtls_platform_entropy_poll() and will rely on getrandom or
     * /dev/urandom in Linux; and on CryptGenRandom() on Windows.
     */
    mbedtls_ctr_drbg_init(&cn->drbg);
    ret = mbedtls_ctr_drbg_seed(&cn->drbg, mbedtls_entropy_func, &cn->entropy,
                                (const unsigned char*)PERSONALIZATION_STRING, sizeof(PERSONALIZATION_STRING) - 1);
    if (ret != 0) {
        DPS_ERRPRINT("Seeding mbedtls random byte generator failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_cookie_init(&cn->cookieCtx);
        ret = mbedtls_ssl_cookie_setup(&cn->cookieCtx, mbedtls_ctr_drbg_random, &cn->drbg);
        if (ret != 0) {
            DPS_ERRPRINT("Setting up mbedtls cookie context failed: %s\n", TLSErrTxt(ret));
            goto ErrorExit;
        }

        mbedtls_ssl_cache_init(&cn->cacheCtx);
    }

    mbedtls_ssl_config_init(&cn->conf);
    ret = mbedtls_ssl_config_defaults(&cn->conf, cn->type, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        DPS_ERRPRINT("Setting mbedtls configuration defaults failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }
    mbedtls_ssl_conf_dbg(&cn->conf, OnTLSDebug, NULL);
    mbedtls_ssl_conf_rng(&cn->conf, mbedtls_ctr_drbg_random, &cn->drbg);
    mbedtls_ssl_conf_handshake_timeout(&cn->conf, netCtx->handshakeTimeoutMin, netCtx->handshakeTimeoutMax);

    memset(&request, 0, sizeof(request));
    request.keyStore = keyStore;
    request.data = cn;

    mbedtls_x509_crt_init(&cn->cacert);
    if (!keyStore->caHandler) {
        ciphersuites = PskCipherSuites;
    } else {
        request.setCA = SetCA;
        ret = keyStore->caHandler(&request);
        if (ret == 0) {
            mbedtls_ssl_conf_ca_chain(&cn->conf, &cn->cacert, NULL);
        } else {
            DPS_WARNPRINT("Parsing trusted certificate(s) failed: %s\n", DPS_ErrTxt(ret));
            ciphersuites = PskCipherSuites;
        }
        request.setCA = NULL;
    }
    mbedtls_x509_crt_init(&cn->cert);
    mbedtls_pk_init(&cn->pkey);
    if (!keyStore->keyHandler) {
        ciphersuites = PskCipherSuites;
    } else {
        request.setKey = SetCert;
        ret = keyStore->keyHandler(&request, &node->signer.kid);
        if (ret == 0) {
            mbedtls_ssl_conf_own_cert(&cn->conf, &cn->cert, &cn->pkey);
        } else {
            DPS_WARNPRINT("Parsing certificate failed: %s\n", DPS_ErrTxt(ret));
            ciphersuites = PskCipherSuites;
        }
        request.setKey = NULL;
    }

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_conf_session_cache(&cn->conf, &cn->cacheCtx, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
        mbedtls_ssl_conf_dtls_cookies(&cn->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cn->cookieCtx);
        mbedtls_ssl_conf_psk_cb(&cn->conf, OnTLSPSKGet, cn);
    } else if (keyStore->keyAndIdHandler) {
        request.setKeyAndId = SetKeyAndId;
        ret = keyStore->keyAndIdHandler(&request);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
        }
        request.setKeyAndId = NULL;
    }
    for (const int* cs = ciphersuites; *cs; ++cs) {
        DPS_DBGPRINT("  %s\n", mbedtls_ssl_get_ciphersuite_name(*cs));
    }
    mbedtls_ssl_conf_ciphersuites(&cn->conf, ciphersuites);
    mbedtls_ssl_conf_authmode(&cn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_init(&cn->ssl);
    mbedtls_ssl_set_bio(&cn->ssl, cn, OnTLSSend, OnTLSRecv, NULL);
    mbedtls_ssl_set_timer_cb(&cn->ssl, cn, OnTLSTimerSet, OnTLSTimerGet);
    ret = mbedtls_ssl_setup(&cn->ssl, &cn->conf);
    if (ret != 0) {
        DPS_ERRPRINT("Setting up mbedtls ssl context failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        ret = ResetConnection(cn, addr);
        if (ret != 0) {
            DPS_ERRPRINT("Reset connection failed: %s\n", TLSErrTxt(ret));
            goto ErrorExit;
        }
    }

    cn->next = netCtx->cns;
    netCtx->cns = cn;
    DPS_DBGPRINT("Created cn=%p\n", cn);
    return cn;

 ErrorExit:
    DestroyConnection(cn);
    return NULL;
}

static void OnIdleForSendCallbacks(uv_idle_t* idle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)idle->data;

    DPS_DBGTRACE();

    while (!DPS_QueueEmpty(&cn->sendCompletedQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendCompletedQueue);
        DPS_QueueRemove(&req->queue);
        req->sendCompleteCB(cn->node, req->appCtx, &cn->peer, req->bufs, req->numBufs, req->status);
        DPS_NetConnectionDecRef(cn);
        DestroySendRequest(req);
    }

    uv_idle_stop(&cn->idleForSendCallbacks);
    DPS_NetConnectionDecRef(cn);
}

/*
 * TRIGGERING THE STATE MACHINE
 *
 * There are three main ways to trigger the mbedtls state machine: ask
 * for perform a handshake step, ask it to read data, and ask it to
 * write data. Until the handshake is done, just the first action is
 * valid.
 *
 * The functions below essentially wrap the mbedtls calls adding
 * debugging and handling our data structures.
 */

static void TLSSend(DPS_NetConnection* cn)
{
    int ret;
    uint8_t* base;
    DPS_TxBuffer txbuf;
    size_t total;

    DPS_DBGTRACEA("cn=%p\n", cn);

    if (DPS_QueueEmpty(&cn->sendQueue)) {
        DPS_DBGPRINT("No pending sends\n");
        return;
    }
    SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
    DPS_QueueRemove(&req->queue);

    DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    if (!uv_is_active((uv_handle_t*)&cn->idleForSendCallbacks)) {
        ret = uv_idle_start(&cn->idleForSendCallbacks, OnIdleForSendCallbacks);
        if (ret == 0) {
            /*
             * Add a ref while OnIdleForSendCallbacks is pending.
             */
            DPS_NetConnectionIncRef(cn);
        }
    }
    DPS_DBGPRINT("Using pending send with %d bufs\n", req->numBufs);

    if (req->numBufs == 1) {
        total = req->bufs[0].len;
        base = (uint8_t*)req->bufs[0].base;
    } else {
        total = 0;
        for (size_t i = 0; i < req->numBufs; i++) {
            total += req->bufs[i].len;
        }

        /*
         * DPS_NetSend follows libuv and let the user send multiple
         * buffers. These are automatically merged together. However
         * mbedtls expects a single buffer.
         */
        ret = DPS_TxBufferInit(&txbuf, NULL, total);
        if (ret != DPS_OK) {
            req->status = DPS_ERR_RESOURCES;
            return;
        }
        for (size_t i = 0; i < req->numBufs; i++) {
            DPS_TxBufferAppend(&txbuf, (uint8_t*)req->bufs[i].base, req->bufs[i].len);
        }
        base = txbuf.base;
    }

    DPS_DBGPRINT("Writing %d bytes of plaintext via DTLS\n", total);
    DPS_DBGBYTES(base, total);

    /*
     * Protect cn since mbedtls_ssl_write may consume all the
     * references.
     */
    DPS_NetConnectionIncRef(cn);

    /*
     * HERE: there's no data pointer to make a connection between this
     * SendRequest and whatever we are going to write in the udp
     * socket. Maybe it is implicit that after this call our udp
     * callback was called, so we stitch things together after the
     * call.
     */
    ret = 0;
    do {
        base = base + ret;
        total = total - ret;
        ret = mbedtls_ssl_write(&cn->ssl, base, total);
    } while (0 < ret && (size_t)ret < total);

    DPS_NetConnectionDecRef(cn);

    if (req->numBufs != 1) {
        DPS_TxBufferFree(&txbuf);
    }

    if (ret < 0) {
        DPS_ERRPRINT("TLS write failed: %s\n", TLSErrTxt(ret));
        req->status = DPS_ERR_NETWORK;
    }
}

static void TLSRecv(DPS_NetConnection* cn)
{
    DPS_NetContext* netCtx = cn->netCtx;
    DPS_NetRxBuffer* buf = NULL;
    int ret;
    DPS_Status status;

    /*
     * Protect cn since mbedtls_ssl_read may consume all the
     * references.
     */
    DPS_NetConnectionIncRef(cn);

    buf = DPS_CreateNetRxBuffer(MAX_READ_LEN);
    if (!buf) {
        DPS_ERRPRINT("Create buffer failed: %s\n", DPS_ErrTxt(DPS_ERR_RESOURCES));
        goto Exit;
    }
    ret = mbedtls_ssl_read(&cn->ssl, buf->rx.base, DPS_RxBufferAvail(&buf->rx));
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            DPS_DBGPRINT("Connection was closed gracefully\n");
            switch (cn->state) {
            case CN_OPEN:
                cn->state = CN_CLOSE_NOTIFIED;
            case CN_CLOSE_NOTIFIED:
            case CN_CLOSING:
                break;
            }
            status = DPS_ERR_EOF;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            DPS_DBGPRINT("Want read cn=%p\n", cn);
            goto Exit;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            DPS_DBGPRINT("Want write cn=%p\n", cn);
            goto Exit;
        } else {
            DPS_WARNPRINT("Failed - %s\n", TLSErrTxt(ret));
            status = DPS_ERR_NETWORK;
        }
    } else {
        buf->rx.eod = &buf->rx.base[ret];
        DPS_DBGPRINT("Decrypted into %d bytes of plaintext\n", buf->rx.eod - buf->rx.base);
        DPS_DBGBYTES(buf->rx.base, buf->rx.eod - buf->rx.base);

        status = DPS_OK;
    }

    ret = netCtx->receiveCB(netCtx->node, &cn->peer, status, buf);

    /*
     * See comment in TLSHandshake about holding onto a reference
     * until the incoming data is received after the handshake is
     * complete.
     */
    if (cn->handshake == MBEDTLS_ERR_SSL_WANT_READ) {
        assert(cn->refCount > 1);
        DPS_NetConnectionDecRef(cn);
        cn->handshake = 0;
    }

Exit:
    DPS_NetRxBufferDecRef(buf);
    DPS_NetConnectionDecRef(cn);
}

static int TLSHandshake(DPS_NetConnection* cn)
{
    int ret;

    DPS_DBGTRACEA("cn=%p\n", cn);

    /*
     * Protect cn since mbedtls_ssl_handshake may consume all the
     * references.
     *
     * Note: When mbedtls_ssl_handshake returns
     * MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED, no pending data or
     * callbacks exist.  This would normally result in destroying the
     * connection.  But we want the connection to remain open until
     * the handshake is complete, hence the special handling below.
     */
    switch (cn->handshake) {
    case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        break;
    default:
        DPS_NetConnectionIncRef(cn);
        break;
    }

    ret = mbedtls_ssl_handshake(&cn->ssl);
    cn->handshake = ret;

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        DPS_DBGPRINT("Hello verification required, resetting cn=%p\n", cn);
        ret = ResetConnection(cn, (const struct sockaddr*)&cn->peer.addr.u.inaddr);
        if (ret != 0) {
            DPS_ERRPRINT("Reset connection failed - %s\n", TLSErrTxt(ret));
            ret = 0;
        }
        goto Exit;
    }

    /*
     * The two cases below just let us know that handshake is waiting for more
     * data to be sent or received.
     */
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        DPS_DBGPRINT("Want read cn=%p\n", cn);
        ret = 0;
        goto Exit;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        DPS_DBGPRINT("Want write cn=%p\n", cn);
        ret = 0;
        goto Exit;
    }

    /*
     * The configured authmode (verify required) will result in
     * hitting this block on any credential verification failures:
     * there is no need for us to do the verification as well.
     */
    if (ret != 0) {
        DPS_WARNPRINT("TLSHandshake failed- %s\n", TLSErrTxt(ret));
        goto Exit;
    }

    /* Handshake is done, consume anything pending. */
    cn->handshakeDone = DPS_TRUE;
    DPS_DBGPRINT("Handshake is done cn=%p\n", cn);

    /*
     * There may not be anything pending yet for a server (incoming)
     * connection.  We want to wait until some data comes in before we
     * destroy the connection, so massage the state here.
     */
    if ((cn->type == MBEDTLS_SSL_IS_SERVER) && (cn->netCtx->state == NET_RUNNING)) {
        cn->handshake = MBEDTLS_ERR_SSL_WANT_READ;
    }

    ConsumePending(cn);
    ret = 0;

 Exit:
    switch (cn->handshake) {
    case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        break;
    default:
        DPS_NetConnectionDecRef(cn);
        break;
    }
    return !ret;
}

static void ConsumePending(DPS_NetConnection* cn)
{
    assert(cn->handshakeDone);
    while (!DPS_QueueEmpty(&cn->recvQueue)) {
        TLSRecv(cn);
    }
    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        TLSSend(cn);
    }
}

static void OnUdpData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_NetContext* netCtx = socket->data;
    RecvData* data = NULL;
    DPS_NodeAddress* nodeAddr = NULL;
    DPS_NetConnection* cn;

    DPS_DBGTRACEA("nread=%d,addr=%s\n", nread, DPS_NetAddrText(addr));

    assert(buf);
    data = CreateRecvData(nread, buf);
    if (!data) {
        goto Exit;
    }

    if (nread < 0) {
        DPS_ERRPRINT("OnData error- %s\n", uv_err_name((int)nread));
        goto Exit;
    }
    if (!nread) {
        goto Exit;
    }
    if (!addr) {
        DPS_ERRPRINT("OnData no address\n");
        goto Exit;
    }
#ifdef _WIN32
    /* Under Windows, data->buf.len is a ULONG, not a size_t */
    if (nread > ULONG_MAX) {
        goto Exit;
    }
#endif
    if (flags & UV_UDP_PARTIAL) {
        DPS_ERRPRINT("Dropping partial message, read buffer too small\n");
        goto Exit;
    }

    nodeAddr = DPS_CreateAddress();
    DPS_NetSetAddr(nodeAddr, DPS_DTLS, addr);

    cn = LookupConnection(netCtx, nodeAddr);
    if (!cn) {
        /*
         * The network layer stops in multiple steps. It happens that
         * in the middle of one of these steps we can receive a
         * message, that can trigger the creation of a connection,
         * leading to more messages to be sent to the network.
         */
        if (netCtx->state == NET_STOPPING) {
            DPS_DBGPRINT("Ignoring incoming data while stopping the network\n");
            goto Exit;
        }
        cn = CreateConnection(netCtx->node, addr, MBEDTLS_SSL_IS_SERVER);
        if (!cn) {
            DPS_ERRPRINT("Create server connection structure failed\n");
            goto Exit;
        }
        cn->peer.addr = *nodeAddr;
        cn->peer.cn = cn;
    } else {
        DPS_DBGPRINT("Found cn=%p,peerAddr=%s\n", cn, DPS_NodeAddrToString(cn->peerAddr));
    }

    /*
     * After the handshake is done, we don't need to use pending
     * structure. It is being used because it is convenient to have
     * one codepath for reading. To improve this must take in
     * consideration that sometimes a connection might be reset (so we
     * need to use pending again).
     */

    DPS_QueuePushBack(&cn->recvQueue, &data->queue);
    data = NULL;
    DPS_NetConnectionIncRef(cn);

    if (!cn->handshakeDone) {
        int ret = TLSHandshake(cn);
        if (ret == DPS_TRUE && cn->handshakeDone) {
            ConsumePending(cn);
        } else if (ret == DPS_FALSE) {
            CancelPending(cn);
        }
    } else {
        TLSRecv(cn);
    }

 Exit:
    DestroyRecvData(data);
    DPS_DestroyAddress(nodeAddr);
}

DPS_NetContext* DPS_NetStart(DPS_Node* node, const DPS_NodeAddress* addr, DPS_OnReceive cb)
{
    int ret;
    DPS_NetContext* netCtx;
    struct sockaddr* sa;
    DPS_NodeAddress any;

    DPS_DBGTRACEA("node=%p,addr=%s,cb=%p\n", node, DPS_NodeAddrToString(addr), cb);

    netCtx = calloc(1, sizeof(DPS_NetContext));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_udp_init(node->loop, &netCtx->rxSocket);
    if (ret) {
        DPS_ERRPRINT("UDP init failed: %s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->dataCB = OnUdpData;
    netCtx->handshakeTimeoutMin = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN;
    netCtx->handshakeTimeoutMax = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX;
    netCtx->node = node;
    netCtx->receiveCB = cb;
    if (addr) {
        sa = (struct sockaddr*)&addr->u.inaddr;
    } else {
        if (!DPS_SetAddress(&any, "[::]:0")) {
            goto ErrorExit;
        }
        sa = (struct sockaddr*)&any.u.inaddr;
    }
    netCtx->rxSocket.data = netCtx;
    ret = uv_udp_bind(&netCtx->rxSocket, sa, 0);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_udp_recv_start(&netCtx->rxSocket, AllocBuffer, OnServerData);
    if (ret) {
        goto ErrorExit;
    }

    mbedtls_debug_set_threshold(DEBUG_MBEDTLS_LEVEL);

    netCtx->state = NET_RUNNING;
    DPS_DBGPRINT("Created netCtx=%p\n", netCtx);
    return netCtx;

ErrorExit:
    DPS_ERRPRINT("Net start failed- %s\n", uv_err_name(ret));
    uv_close((uv_handle_t*)&netCtx->rxSocket, RxHandleClosed);
    return NULL;
}

DPS_NodeAddress* DPS_NetGetListenAddress(DPS_NodeAddress* addr, DPS_NetContext* netCtx)
{
    int len;

    DPS_DBGTRACEA("netCtx=%p\n", netCtx);

    memzero_s(addr, sizeof(DPS_NodeAddress));
    if (!netCtx) {
        return addr;
    }
    addr->type = DPS_DTLS;
    len = sizeof(struct sockaddr_in6);
    if (uv_udp_getsockname(&netCtx->rxSocket, (struct sockaddr*)&addr->u.inaddr, &len)) {
        return addr;
    }
    DPS_DBGPRINT("Listener address = %s\n", DPS_NodeAddrToString(addr));
    return addr;
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    DPS_NetConnection* cns;

    DPS_DBGTRACEA("netCtx=%p\n", netCtx);

    if (!netCtx) {
        return;
    }

    if (netCtx->state == NET_RUNNING) {
        netCtx->state = NET_STOPPING;
        /*
         * To safely close the rxSocket we need to ensure that no
         * connections will reference it.
         */
        cns = netCtx->cns;
        while (cns) {
            DPS_NetConnection* cn = cns;
            cns = cns->next;
            CancelPending(cn);
        }
        /*
         * When no connections are active we can close the rxSocket
         * immediately.  Otherwise we must wait for FreeConnection to
         * be called to ensure no one is using the rxSocket.
         */
        if (!netCtx->cns) {
            uv_udp_recv_stop(&netCtx->rxSocket);
            uv_close((uv_handle_t*)&netCtx->rxSocket, RxHandleClosed);
        }
    }
}

DPS_Status DPS_NetSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs,
                       DPS_NetSendComplete sendCompleteCB)
{
    SendRequest* req;

    DPS_DBGTRACEA("node=%p,appCtx=%p,ep={addr=%s,cn=%p},bufs=%p,numBufs=%p,sendCompleteCB=%p\n",
                  node, appCtx, DPS_NodeAddrToString(&ep->addr), ep->cn, bufs, numBufs, sendCompleteCB);

#ifdef DPS_DEBUG
    {
        size_t i;
        size_t len = 0;
        for (i = 0; i < numBufs; ++i) {
            len += bufs[i].len;
        }
        DPS_DBGPRINT("DPS_NetSend total %zu bytes to %s\n", len, DPS_NodeAddrToString(&ep->addr));
    }
#endif

    req = CreateSendRequest(appCtx, bufs, numBufs, sendCompleteCB);
    if (!req) {
        return DPS_ERR_RESOURCES;
    }

    if (ep->cn) {
        int queueEmpty;
        req->cn = ep->cn;
        queueEmpty= DPS_QueueEmpty(&ep->cn->sendQueue);
        DPS_QueuePushBack(&ep->cn->sendQueue, &req->queue);
        DPS_NetConnectionIncRef(ep->cn);
        if (queueEmpty && ep->cn->handshakeDone) {
            TLSSend(ep->cn);
        }
        return DPS_OK;
    }
    ep->cn = CreateConnection(node, (const struct sockaddr*)&ep->addr.u.inaddr, MBEDTLS_SSL_IS_CLIENT);
    if (!ep->cn) {
        goto ErrorExit;
    }
    ep->cn->peer = *ep;
    if (!TLSHandshake(ep->cn)) {
        goto ErrorExit;
    }
    /*
     * Add the pending send to the queue now that DPS_NetSend will
     * return DPS_OK (the send complete callback should not be called
     * if DPS_NetSend returns an error).
     */
    req->cn = ep->cn;
    DPS_QueuePushBack(&ep->cn->sendQueue, &req->queue);
    req = NULL;
    DPS_NetConnectionIncRef(ep->cn);
    if (ep->cn->handshakeDone) {
        ConsumePending(ep->cn);
    }
    /* The caller gets a ref count to own. */
    DPS_NetConnectionIncRef(ep->cn);
    return DPS_OK;

 ErrorExit:
    DestroySendRequest(req);
    if (ep->cn && ep->cn->refCount == 0) {
        DestroyConnection(ep->cn);
    }
    ep->cn = NULL;
    return DPS_ERR_NETWORK;
}

void DPS_NetConnectionIncRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACEA("cn=%p\n", cn);
        ++cn->refCount;
    }
}

void DPS_NetConnectionDecRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACEA("cn=%p\n", cn);
        assert(cn->refCount > 0);
        if (--cn->refCount == 0) {
            DestroyConnection(cn);
        }
    }
}

#ifdef DPS_USE_FUZZ
uv_udp_recv_cb Fuzz_OnData(DPS_Node* node, uv_udp_recv_cb cb)
{
    DPS_NetContext* netCtx = node->netCtx;
    uv_udp_recv_cb ret;

    /*
     * Shorten the handshake timeouts so that fuzzing can proceed
     * rapidly
     */
    netCtx->handshakeTimeoutMin = 10;
    netCtx->handshakeTimeoutMax = 100;

    ret = netCtx->dataCB;
    netCtx->dataCB = cb;
    return ret;
}
#endif /* DPS_USE_FUZZ */
