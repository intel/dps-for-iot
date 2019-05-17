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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <safe_lib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include "../node.h"
#include "../queue.h"

#ifdef _WIN32
#include <netioapi.h>
#else
#include <net/if.h>
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _DPS_NetTcpConnection DPS_NetTcpConnection;

typedef struct _SendRequest {
    DPS_Queue queue;
    DPS_NetTcpConnection* cn;
    uv_write_t writeReq;
    DPS_NetSendComplete onSendComplete;
    void* appCtx;
    DPS_Status status;
    size_t numBufs;
    uint8_t lenBuf[CBOR_SIZEOF(uint32_t)]; /* pre-allocated buffer for serializing message length */
    uv_buf_t bufs[1];
} SendRequest;

typedef struct _DPS_NetTcpConnection {
    DPS_NetConnection cn;
    DPS_Node* node;
    uv_tcp_t socket;
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
} DPS_NetTcpConnection;

typedef struct _DPS_NetTcpContext {
    DPS_NetContext ctx;
    uv_tcp_t socket;   /* the listen socket */
    DPS_Node* node;
    DPS_OnReceive receiveCB;
} DPS_NetTcpContext;

#define MIN_READ_SIZE        CBOR_SIZEOF(uint32_t)

DPS_NodeAddress* DPS_NetTcpGetListenAddress(DPS_NodeAddress* addr, DPS_NetContext* netCtx);
void DPS_NetTcpStop(DPS_NetContext* netCtx);
DPS_Status DPS_NetTcpSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs,
                          DPS_NetSendComplete sendCompleteCB);
void DPS_NetTcpConnectionIncRef(DPS_NetConnection* cn);
void DPS_NetTcpConnectionDecRef(DPS_NetConnection* cn);
static void Shutdown(DPS_NetTcpConnection* cn);

static void ConnectionIncRef(DPS_NetTcpConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        ++cn->refCount;
    }
}

static void ConnectionDecRef(DPS_NetTcpConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        assert(cn->refCount > 0);
        if (--cn->refCount == 0) {
            Shutdown(cn);
        }
    }
}

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    DPS_NetTcpConnection* cn = (DPS_NetTcpConnection*)handle->data;

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

static void CancelPendingSends(DPS_NetTcpConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
        DPS_QueueRemove(&req->queue);
        DPS_DBGPRINT("Canceling SendRequest=%p\n", req);
        req->status = DPS_ERR_NETWORK;
        DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    }
}

static void SendCompleted(DPS_NetTcpConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendCompletedQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendCompletedQueue);
        DPS_QueueRemove(&req->queue);
        req->onSendComplete(req->cn->node, req->appCtx, &req->cn->peerEp, req->bufs + 1, req->numBufs - 1,
                            req->status);
        free(req);
    }
}

static void SendCompletedTask(uv_idle_t* idle)
{
    DPS_NetTcpConnection* cn = idle->data;
    SendCompleted(cn);
    uv_idle_stop(idle);
}

static void FreeConnection(DPS_NetTcpConnection* cn)
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
    DPS_NetTcpConnection* cn = handle->data;
    FreeConnection(cn);
}

static void StreamClosed(uv_handle_t* handle)
{
    DPS_NetTcpConnection* cn = (DPS_NetTcpConnection*)handle->data;

    DPS_DBGPRINT("Closed stream handle %p\n", handle);
    if (!uv_is_closing((uv_handle_t*)&cn->idle)) {
        uv_close((uv_handle_t*)&cn->idle, IdleClosed);
    }
}

static void OnShutdownComplete(uv_shutdown_t* req, int status)
{
    DPS_NetTcpConnection* cn = (DPS_NetTcpConnection*)req->data;

    DPS_DBGPRINT("Shutdown complete handle %p\n", req->handle);
    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        req->handle->data = cn;
        uv_close((uv_handle_t*)req->handle, StreamClosed);
    }
}

static void Shutdown(DPS_NetTcpConnection* cn)
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
    DPS_NetTcpConnection* cn = (DPS_NetTcpConnection*)socket->data;
    DPS_NetTcpContext* netCtx = (DPS_NetTcpContext*)cn->node->netCtx;

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
    DPS_NetTcpContext* netCtx = (DPS_NetTcpContext*)stream->data;
    DPS_NetTcpConnection* cn;
    int sz = sizeof(cn->peerEp.addr.u.inaddr);

    DPS_DBGTRACE();

    if (netCtx->node->state != DPS_NODE_RUNNING) {
        return;
    }
    if (status < 0) {
        DPS_ERRPRINT("OnIncomingConnection %s\n", uv_strerror(status));
        goto FailConnection;
    }

    cn = calloc(1, sizeof(DPS_NetTcpConnection));
    if (!cn) {
        DPS_ERRPRINT("OnIncomingConnection malloc failed\n");
        goto FailConnection;
    }
    cn->cn.incRef = DPS_NetTcpConnectionIncRef;
    cn->cn.decRef = DPS_NetTcpConnectionDecRef;
    ret = uv_tcp_init(stream->loop, &cn->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(cn);
        goto FailConnection;
    }
    cn->node = netCtx->node;
    cn->socket.data = cn;
    cn->peerEp.cn = (DPS_NetConnection*)cn;
    DPS_QueueInit(&cn->sendQueue);
    DPS_QueueInit(&cn->sendCompletedQueue);
    uv_idle_init(stream->loop, &cn->idle);
    cn->idle.data = cn;

    ret = uv_accept(stream, (uv_stream_t*)&cn->socket);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection accept %s\n", uv_strerror(ret));
        goto FailConnection;
    }
    cn->peerEp.addr.type = DPS_TCP;
    uv_tcp_getpeername((uv_tcp_t*)&cn->socket, (struct sockaddr*)&cn->peerEp.addr.u.inaddr, &sz);
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

DPS_NetContext* DPS_NetTcpStart(DPS_Node* node, const DPS_NodeAddress* addr, DPS_OnReceive cb)
{
    static struct sockaddr_storage sszero = { 0 };
    int ret;
    DPS_NetTcpContext* netCtx;
    struct sockaddr* sa;
    DPS_NodeAddress any;

    netCtx = calloc(1, sizeof(DPS_NetTcpContext));
    if (!netCtx) {
        return NULL;
    }
    netCtx->ctx.getListenAddress = DPS_NetTcpGetListenAddress;
    netCtx->ctx.stop = DPS_NetTcpStop;
    netCtx->ctx.send = DPS_NetTcpSend;
    ret = uv_tcp_init(node->loop, &netCtx->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->node = node;
    netCtx->receiveCB = cb;
    if (addr && memcmp(&addr->u.inaddr, &sszero, sizeof(struct sockaddr_storage))) {
        sa = (struct sockaddr*)&addr->u.inaddr;
    } else {
        if (!DPS_SetAddress(&any, "tcp", "[::]:0")) {
            goto ErrorExit;
        }
        sa = (struct sockaddr*)&any.u.inaddr;
    }
    ret = uv_tcp_bind(&netCtx->socket, sa, 0);
    if (ret) {
        goto ErrorExit;
    }
    netCtx->socket.data = netCtx;
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
    return (DPS_NetContext*)netCtx;

ErrorExit:

    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    netCtx->socket.data = netCtx;
    uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    return NULL;
}

DPS_NodeAddress* DPS_NetTcpGetListenAddress(DPS_NodeAddress* addr, DPS_NetContext* ctx)
{
    DPS_NetTcpContext* netCtx = (DPS_NetTcpContext*)ctx;
    int len;

    DPS_DBGTRACEA("netCtx=%p\n", netCtx);

    memzero_s(addr, sizeof(DPS_NodeAddress));
    if (!netCtx) {
        return addr;
    }
    addr->type = DPS_TCP;
    len = sizeof(struct sockaddr_in6);
    if (uv_tcp_getsockname(&netCtx->socket, (struct sockaddr*)&addr->u.inaddr, &len)) {
        return addr;
    }
    DPS_DBGPRINT("Listener address = %s\n", DPS_NodeAddrToString(addr));
    return addr;
}

void DPS_NetTcpStop(DPS_NetContext* ctx)
{
    DPS_NetTcpContext* netCtx = (DPS_NetTcpContext*)ctx;

    if (netCtx) {
        netCtx->socket.data = netCtx;
        uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    }
}

static void OnWriteComplete(uv_write_t* writeReq, int status)
{
    SendRequest* req = (SendRequest*)writeReq->data;
    DPS_NetTcpConnection* cn = req->cn;

    if (status) {
        DPS_DBGPRINT("OnWriteComplete status=%s\n", uv_err_name(status));
        req->status = DPS_ERR_NETWORK;
    } else {
        req->status = DPS_OK;
    }
    DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
    SendCompleted(cn);
    ConnectionDecRef(cn);
}

static void DoSend(DPS_NetTcpConnection* cn)
{
    while (!DPS_QueueEmpty(&cn->sendQueue)) {
        SendRequest* req = (SendRequest*)DPS_QueueFront(&cn->sendQueue);
        DPS_QueueRemove(&req->queue);
        req->writeReq.data = req;
        int r = uv_write(&req->writeReq, (uv_stream_t*)&cn->socket, req->bufs, (uint32_t)req->numBufs,
                         OnWriteComplete);
        if (r == 0) {
            ConnectionIncRef(cn);
        } else {
            DPS_ERRPRINT("DoSend - write failed: %s\n", uv_err_name(r));
            req->status = DPS_ERR_NETWORK;
            DPS_QueuePushBack(&cn->sendCompletedQueue, &req->queue);
        }
    }
}

static void OnOutgoingConnection(uv_connect_t *req, int status)
{
    DPS_NetTcpConnection* cn = (DPS_NetTcpConnection*)req->data;
    if (status == 0) {
        cn->socket.data = cn;
        status = uv_read_start((uv_stream_t*)&cn->socket, AllocBuffer, OnData);
    }
    if (status == 0) {
        DoSend(cn);
    } else {
        DPS_ERRPRINT("OnOutgoingConnection - connect %s failed: %s\n", DPS_NodeAddrToString(&cn->peerEp.addr),
                     uv_err_name(status));
        assert(!DPS_QueueEmpty(&cn->sendQueue));
        CancelPendingSends(cn);
    }
    SendCompleted(cn);
}

DPS_Status DPS_NetTcpSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs,
                          size_t numBufs, DPS_NetSendComplete sendCompleteCB)
{
    DPS_Status ret;
    DPS_TxBuffer lenBuf;
    SendRequest* req;
    DPS_NetTcpConnection* cn = NULL;
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
        cn = (DPS_NetTcpConnection*)ep->cn;
        req->cn = cn;
        /*
         * If there are pending sends the connection is not up yet
         */
        if (!DPS_QueueEmpty(&cn->sendQueue)) {
            DPS_QueuePushBack(&cn->sendQueue, &req->queue);
            return DPS_OK;
        }
        DPS_QueuePushBack(&cn->sendQueue, &req->queue);
        DoSend(cn);
        uv_idle_start(&cn->idle, SendCompletedTask);
        return DPS_OK;
    }

    cn = calloc(1, sizeof(DPS_NetTcpConnection));
    if (!cn) {
        goto ErrExit;
    }
    cn->cn.incRef = DPS_NetTcpConnectionIncRef;
    cn->cn.decRef = DPS_NetTcpConnectionDecRef;
    r = uv_tcp_init(node->loop, &cn->socket);
    if (r) {
        goto ErrExit;
    }
    cn->peerEp.addr = ep->addr;
    cn->node = node;
    DPS_QueueInit(&cn->sendQueue);
    DPS_QueueInit(&cn->sendCompletedQueue);
    uv_idle_init(node->loop, &cn->idle);
    cn->idle.data = cn;
    socket = (uv_handle_t*)&cn->socket;

    if (ep->addr.u.inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)&ep->addr.u.inaddr;
        if (!in6->sin6_scope_id) {
            in6->sin6_scope_id = GetScopeId(in6);
        }
    }
    cn->connectReq.data = cn;
    r = uv_tcp_connect(&cn->connectReq, &cn->socket, (struct sockaddr*)&ep->addr.u.inaddr,
                       OnOutgoingConnection);
    if (r) {
        DPS_ERRPRINT("uv_tcp_connect %s error=%s\n", DPS_NodeAddrToString(&ep->addr), uv_err_name(r));
        goto ErrExit;
    }
    cn->peerEp.cn = (DPS_NetConnection*)cn;
    DPS_QueuePushBack(&cn->sendQueue, &req->queue);
    req->cn = cn;
    ConnectionIncRef(cn);
    ep->cn = (DPS_NetConnection*)cn;
    return DPS_OK;

ErrExit:

    if (req) {
        free(req);
    }
    if (socket) {
        socket->data = cn;
        uv_close(socket, StreamClosed);
    } else {
        if (cn) {
            free(cn);
        }
    }
    ep->cn = NULL;
    return DPS_ERR_NETWORK;
}

void DPS_NetTcpConnectionIncRef(DPS_NetConnection* cn)
{
    ConnectionIncRef((DPS_NetTcpConnection*)cn);
}

void DPS_NetTcpConnectionDecRef(DPS_NetConnection* cn)
{
    ConnectionDecRef((DPS_NetTcpConnection*)cn);
}

DPS_NetTransport DPS_NetTcpTransport = {
    DPS_TCP,
    DPS_NetTcpStart
};
