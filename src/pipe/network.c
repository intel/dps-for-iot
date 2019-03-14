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

#include <safe_lib.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include "../node.h"
#include "../queue.h"

#ifdef _WIN32
#include <netioapi.h>
#define PATH_SEP "\\"
#else
#include <net/if.h>
#include <sys/un.h>
#define PATH_SEP "/"
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _SendRequest {
    DPS_Queue queue;
    DPS_NetConnection* cn;
    uv_write_t writeReq;
    DPS_NetSendComplete onSendComplete;
    void* appCtx;
    DPS_Status status;
    size_t numBufs;
    uint8_t lenBuf[CBOR_SIZEOF(uint32_t)]; /* pre-allocated buffer for serializing message length */
    uv_buf_t bufs[1];
} SendRequest;

typedef struct _DPS_NetConnection {
    DPS_Node* node;
    uv_pipe_t socket;
    DPS_NetEndpoint peerEp;
    int refCount;
    uv_shutdown_t shutdownReq;
    /* Rx side */
    uint8_t lenBuf[CBOR_SIZEOF(uint32_t)]; /* pre-allocated buffer for deserializing message length */
    size_t readLen; /* how much data has already been read */
    DPS_NetRxBuffer* msgBuf;
    /* Tx side */
    uv_connect_t connectReq;
    DPS_Queue sendQueue;
    DPS_Queue sendCompletedQueue;
    uv_idle_t idle;
} DPS_NetConnection;

struct _DPS_NetContext {
    uv_pipe_t socket;   /* the listen socket */
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

#define MIN_BUF_ALLOC_SIZE   512
#define MIN_READ_SIZE        CBOR_SIZEOF(uint32_t)

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;

    if (cn->msgBuf) {
        buf->len = DPS_RxBufferAvail(&cn->msgBuf->rx);
        buf->base = (char*)cn->msgBuf->rx.rxPos;
    } else {
        buf->len = (uint32_t)(sizeof(cn->lenBuf) - cn->readLen);
        buf->base = (char*)(cn->lenBuf + cn->readLen);
    }
}

static void ListenSocketClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed handle %p\n", handle);
    free(handle->data);
}

static void CancelPendingSends(DPS_NetConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
        DPS_QueueRemove(&req->queue);
        DPS_DBGPRINT("Canceling SendRequest=%p\n", req);
        req->status = DPS_ERR_NETWORK;
        DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    }
}

static void SendCompleted(DPS_NetConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendCompletedQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendCompletedQueue);
        DPS_QueueRemove(&req->queue);
        req->onSendComplete(req->cn->node, req->appCtx, &req->cn->peerEp, req->bufs + 1,
                            req->numBufs - 1, req->status);
        free(req);
    }
}

static void SendCompletedTask(uv_idle_t* idle)
{
    DPS_NetConnection* cn = idle->data;
    SendCompleted(cn);
    uv_idle_stop(idle);
}

static void FreeConnection(DPS_NetConnection* cn)
{
    /*
     * Free memory for any pending sends
     */
    CancelPendingSends(cn);
    SendCompleted(cn);
    DPS_NetRxBufferDecRef(cn->msgBuf);
    cn->msgBuf = NULL;
    free(cn);
}

static void IdleClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = handle->data;
    FreeConnection(cn);
}

static void StreamClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;

    DPS_DBGPRINT("Closed stream handle %p\n", handle);
    if (!uv_is_closing((uv_handle_t*)&cn->idle)) {
        uv_close((uv_handle_t*)&cn->idle, IdleClosed);
    }
}

static void OnShutdownComplete(uv_shutdown_t* req, int status)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)req->data;

    DPS_DBGPRINT("Shutdown complete handle %p\n", req->handle);
    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        req->handle->data = cn;
        uv_close((uv_handle_t*)req->handle, StreamClosed);
    }
}

static void Shutdown(DPS_NetConnection* cn)
{
    if (!cn->shutdownReq.data) {
        int r;
        assert(cn->refCount == 0);
        uv_read_stop((uv_stream_t*)&cn->socket);
        cn->shutdownReq.data = cn;
        r = uv_shutdown(&cn->shutdownReq, (uv_stream_t*)&cn->socket, OnShutdownComplete);
        if (r) {
            DPS_ERRPRINT("Shutdown failed %s - closing\n", uv_err_name(r));
            if (!uv_is_closing((uv_handle_t*)&cn->socket)) {
                cn->socket.data = cn;
                uv_close((uv_handle_t*)&cn->socket, StreamClosed);
            }
        }
    }
}

static void OnData(uv_stream_t* socket, ssize_t nread, const uv_buf_t* buf)
{
    DPS_Status ret = DPS_OK;
    DPS_NetConnection* cn = (DPS_NetConnection*)socket->data;
    DPS_NetContext* netCtx = cn->node->netCtx;

    DPS_DBGTRACE();
    /*
     * netCtx will be null if we are shutting down
     */
    if (!netCtx) {
        return;
    }
    /*
     * libuv does this...
     */
    if (nread == 0) {
        return;
    }
    if (nread < 0) {
        uv_read_stop(socket);
        netCtx->receiveCB(cn->node, &cn->peerEp, nread == UV_EOF ? DPS_ERR_EOF : DPS_ERR_NETWORK, NULL);
        return;
    }
    assert(socket == (uv_stream_t*)&cn->socket);

    /*
     * Parse out the message length
     */
    if (!cn->msgBuf) {
        DPS_RxBuffer lenBuf;
        uint32_t msgLen;
        /*
         * Keep reading if we don't have enough data to parse the length
         */
        cn->readLen += nread;
        if (cn->readLen < MIN_READ_SIZE) {
            return;
        }
        assert(cn->readLen == MIN_READ_SIZE);
        DPS_RxBufferInit(&lenBuf, cn->lenBuf, cn->readLen);
        ret = CBOR_DecodeUint32(&lenBuf, &msgLen);
        if (ret == DPS_OK) {
            cn->msgBuf = DPS_CreateNetRxBuffer(msgLen);
            if (cn->msgBuf) {
                /*
                 * Copy message bytes if any
                 */
                memcpy(cn->msgBuf->rx.rxPos, lenBuf.rxPos, DPS_RxBufferAvail(&lenBuf));
                cn->msgBuf->rx.rxPos += DPS_RxBufferAvail(&lenBuf);
            } else {
                ret = DPS_ERR_RESOURCES;
            }
        }
        if (ret != DPS_OK) {
            /*
             * Report error to receive callback
             */
            netCtx->receiveCB(cn->node, &cn->peerEp, ret, NULL);
        }
    } else {
        cn->msgBuf->rx.rxPos += nread;
    }
    if (cn->msgBuf) {
        /*
         * Keep reading if we don't have a complete message
         */
        if (DPS_RxBufferAvail(&cn->msgBuf->rx)) {
            return;
        }
        DPS_DBGPRINT("Received message of length %zd\n", cn->msgBuf->rx.eod - cn->msgBuf->rx.base);
        /*
         * Reset rxPos to beginning of complete message before passing up
         */
        cn->msgBuf->rx.rxPos = cn->msgBuf->rx.base;
        ret = netCtx->receiveCB(cn->node, &cn->peerEp, DPS_OK, cn->msgBuf);
    }
    DPS_NetRxBufferDecRef(cn->msgBuf);
    cn->msgBuf = NULL;
    cn->readLen = 0;
    /*
     * Stop reading if we got an error
     */
    if (ret != DPS_OK) {
        uv_read_stop(socket);
    }
    /*
     * Shutdown the connection if the upper layer didn't IncRef to keep it alive
     */
    if (cn->refCount == 0) {
        Shutdown(cn);
    }
}

static void OnIncomingConnection(uv_stream_t* stream, int status)
{
    int ret;
    DPS_NetContext* netCtx = (DPS_NetContext*)stream->data;
    DPS_NetConnection* cn;
    size_t sz;

    DPS_DBGTRACE();

    if (netCtx->node->state != DPS_NODE_RUNNING) {
        return;
    }
    if (status < 0) {
        DPS_ERRPRINT("OnIncomingConnection %s\n", uv_strerror(status));
        goto FailConnection;
    }

    cn = calloc(1, sizeof(DPS_NetConnection));
    if (!cn) {
        DPS_ERRPRINT("OnIncomingConnection malloc failed\n");
        goto FailConnection;
    }
    ret = uv_pipe_init(stream->loop, &cn->socket, 0);
    if (ret) {
        DPS_ERRPRINT("uv_pipe_init error=%s\n", uv_err_name(ret));
        free(cn);
        goto FailConnection;
    }
    cn->node = netCtx->node;
    cn->socket.data = cn;
    cn->peerEp.cn = cn;
    DPS_QueueInit(&cn->sendQueue);
    DPS_QueueInit(&cn->sendCompletedQueue);
    uv_idle_init(stream->loop, &cn->idle);
    cn->idle.data = cn;

    ret = uv_accept(stream, (uv_stream_t*)&cn->socket);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection accept %s\n", uv_strerror(ret));
        goto FailConnection;
    }
    cn->peerEp.addr.type = DPS_PIPE;
    sz = sizeof(cn->peerEp.addr.u.path);
    uv_pipe_getpeername((uv_pipe_t*)&cn->socket, cn->peerEp.addr.u.path, &sz);
#ifdef _WIN32
    if (!strncmp(cn->peerEp.addr.u.path, "\\\\?", 3)) {
        cn->peerEp.addr.u.path[2] = '.';
    }
#endif
    ret = uv_read_start((uv_stream_t*)&cn->socket, AllocBuffer, OnData);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection read start %s\n", uv_strerror(ret));
        Shutdown(cn);
    }
    return;

FailConnection:

    uv_close((uv_handle_t*)stream, NULL);
}

/*
 * The scope id must be set for link local addresses.
 *
 * TODO - how to handle case where there are multiple interfaces with link local addresses.
 */
static int GetScopeId(struct sockaddr_in6* addr)
{
    if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        static int linkLocalScope = 0;
        if (!linkLocalScope) {
            uv_interface_address_t* ifsAddrs = NULL;
            int numIfs = 0;
            int i;
            uv_interface_addresses(&ifsAddrs, &numIfs);
            for (i = 0; i < numIfs; ++i) {
                uv_interface_address_t* ifn = &ifsAddrs[i];
                if (ifn->is_internal || (ifn->address.address6.sin6_family != AF_INET6)) {
                    continue;
                }
                if (IN6_IS_ADDR_LINKLOCAL(&ifn->address.address6.sin6_addr)) {
                    linkLocalScope = if_nametoindex(ifn->name);
                    break;
                }
            }
            uv_free_interface_addresses(ifsAddrs, numIfs);
        }
        return linkLocalScope;
    }
    return 0;
}

#define LISTEN_BACKLOG  2

DPS_NetContext* DPS_NetStart(DPS_Node* node, const DPS_NodeAddress* addr, DPS_OnReceive cb)
{
    char path[DPS_NODE_ADDRESS_PATH_MAX] = { 0 };
    DPS_NetContext* netCtx = NULL;
    DPS_UUID uuid;
    int ret;

    netCtx = calloc(1, sizeof(DPS_NetContext));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_pipe_init(node->loop, &netCtx->socket, 0);
    if (ret) {
        DPS_ERRPRINT("uv_pipe_init error=%s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->socket.data = netCtx;
    netCtx->node = node;
    netCtx->receiveCB = cb;
    if (addr) {
        ret = uv_pipe_bind(&netCtx->socket, addr->u.path);
    } else {
        /*
         * Create a unique temporary path
         */
        do {
#ifdef _WIN32
            ret = strcat_s(path, sizeof(path), "\\\\.\\pipe");
#else
            size_t len = sizeof(path);
            ret = uv_os_tmpdir(path, &len);
#endif
            if (ret) {
                goto ErrorExit;
            }
            DPS_GenerateUUID(&uuid);
            ret = strcat_s(path, sizeof(path), PATH_SEP);
            if (ret != EOK) {
                goto ErrorExit;
            }
            ret = strcat_s(path, sizeof(path), DPS_UUIDToString(&uuid));
            if (ret != EOK) {
                goto ErrorExit;
            }
            ret = uv_pipe_bind(&netCtx->socket, path);
        } while (ret == EADDRINUSE);
    }
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_listen((uv_stream_t*)&netCtx->socket, LISTEN_BACKLOG, OnIncomingConnection);
    if (ret) {
        goto ErrorExit;
    }
    DPS_DBGPRINT("Listening on socket %p\n", &netCtx->socket);
#ifndef _WIN32
    /*
     * libuv does not ignore SIGPIPE on Linux
     */
    signal(SIGPIPE, SIG_IGN);
#endif
    return netCtx;

ErrorExit:
    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    return NULL;
}

DPS_NodeAddress* DPS_NetGetListenAddress(DPS_NodeAddress* addr, DPS_NetContext* netCtx)
{
    size_t len;

    DPS_DBGTRACEA("netCtx=%p\n", netCtx);

    memzero_s(addr, sizeof(DPS_NodeAddress));
    if (!netCtx) {
        return addr;
    }
    addr->type = DPS_PIPE;
    len = sizeof(addr->u.path);
    if (uv_pipe_getsockname(&netCtx->socket, addr->u.path, &len)) {
        return addr;
    }
#ifdef _WIN32
    if (!strncmp(addr->u.path, "\\\\?", 3)) {
        addr->u.path[2] = '.';
    }
#endif
    DPS_DBGPRINT("Listener address = %s\n", addr->u.path);
    return addr;
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    if (netCtx) {
        netCtx->socket.data = netCtx;
        uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    }
}

static void OnWriteComplete(uv_write_t* writeReq, int status)
{
    SendRequest* req = (SendRequest*)writeReq->data;
    DPS_NetConnection* cn = req->cn;

    if (status) {
        DPS_DBGPRINT("OnWriteComplete status=%s\n", uv_err_name(status));
        req->status = DPS_ERR_NETWORK;
    } else {
        req->status = DPS_OK;
    }
    DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    SendCompleted(cn);
    DPS_NetConnectionDecRef(cn);
}

static void DoSend(DPS_NetConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
        DPS_QueueRemove(&req->queue);
        req->writeReq.data = req;
        int r = uv_write(&req->writeReq, (uv_stream_t*)&cn->socket, req->bufs, (uint32_t)req->numBufs,
                         OnWriteComplete);
        if (r == 0) {
            DPS_NetConnectionIncRef(cn);
        } else {
            DPS_ERRPRINT("DoSend - write failed: %s\n", uv_err_name(r));
            req->status = DPS_ERR_NETWORK;
            DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
        }
    }
}

static void OnOutgoingConnection(uv_connect_t *req, int status)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)req->data;
    if (status == 0) {
        cn->socket.data = cn;
        status = uv_read_start((uv_stream_t*)&cn->socket, AllocBuffer, OnData);
    }
    if (status == 0) {
        DoSend(cn);
    } else {
        DPS_ERRPRINT("OnOutgoingConnection - connect %s failed: %s\n",
                     DPS_NodeAddrToString(&cn->peerEp.addr), uv_err_name(status));
        assert(!DPS_QueueEmpty(&cn->sendQueue));
        CancelPendingSends(cn);
    }
    SendCompleted(cn);
}

DPS_Status DPS_NetSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs,
                       size_t numBufs, DPS_NetSendComplete sendCompleteCB)
{
    DPS_Status ret;
    DPS_TxBuffer lenBuf;
    SendRequest* req;
    uv_handle_t* socket = NULL;
    int r;
    size_t i;
    size_t len = 0;

    for (i = 0; i < numBufs; ++i) {
        len += bufs[i].len;
    }
    if (len > UINT32_MAX) {
        return DPS_ERR_RESOURCES;
    }

    DPS_DBGPRINT("DPS_NetSend total %zu bytes to %s\n", len, DPS_NodeAddrToString(&ep->addr));

    req = malloc(sizeof(SendRequest) + numBufs * sizeof(uv_buf_t));
    if (!req) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Write total message length
     */
    DPS_TxBufferInit(&lenBuf, req->lenBuf, sizeof(req->lenBuf));
    ret = CBOR_EncodeUint32(&lenBuf, len);
    if (ret != DPS_OK) {
        goto ErrExit;
    }
    req->bufs[0].base = (char*)req->lenBuf;
    req->bufs[0].len = DPS_TxBufferUsed(&lenBuf);
    /*
     * Copy other uvbufs into the send request
     */
    for (i = 0; i < numBufs; ++i) {
        req->bufs[i + 1] = bufs[i];
    }
    req->numBufs = numBufs + 1;
    req->onSendComplete = sendCompleteCB;
    req->appCtx = appCtx;
    /*
     * See if we already have a connection
     */
    if (ep->cn) {
        req->cn = ep->cn;
        /*
         * If there are pending sends the connection is not up yet
         */
        if (!DPS_QueueEmpty(&ep->cn->sendQueue)) {
            DPS_QueuePushBack(&ep->cn->sendQueue, &req->queue);
            return DPS_OK;
        }
        DPS_QueuePushBack(&ep->cn->sendQueue, &req->queue);
        DoSend(ep->cn);
        uv_idle_start(&ep->cn->idle, SendCompletedTask);
        return DPS_OK;
    }

    ep->cn = calloc(1, sizeof(DPS_NetConnection));
    if (!ep->cn) {
        goto ErrExit;
    }
    r = uv_pipe_init(node->loop, &ep->cn->socket, 0);
    if (r) {
        goto ErrExit;
    }
    ep->cn->peerEp.addr = ep->addr;
    ep->cn->node = node;
    DPS_QueueInit(&ep->cn->sendQueue);
    DPS_QueueInit(&ep->cn->sendCompletedQueue);
    uv_idle_init(node->loop, &ep->cn->idle);
    ep->cn->idle.data = ep->cn;
    socket = (uv_handle_t*)&ep->cn->socket;

    ep->cn->connectReq.data = ep->cn;
    uv_pipe_connect(&ep->cn->connectReq, &ep->cn->socket, ep->addr.u.path, OnOutgoingConnection);
    ep->cn->peerEp.cn = ep->cn;
    DPS_QueuePushBack(&ep->cn->sendQueue, &req->queue);
    req->cn = ep->cn;
    DPS_NetConnectionIncRef(ep->cn);
    return DPS_OK;

ErrExit:

    if (req) {
        free(req);
    }
    if (socket) {
        socket->data = ep->cn;
        uv_close(socket, StreamClosed);
    } else {
        if (ep->cn) {
            free(ep->cn);
        }
    }
    ep->cn = NULL;
    return DPS_ERR_NETWORK;
}

void DPS_NetConnectionIncRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        ++cn->refCount;
    }
}

void DPS_NetConnectionDecRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        assert(cn->refCount > 0);
        if (--cn->refCount == 0) {
            Shutdown(cn);
        }
    }
}
