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
#include <malloc.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "../cbor.h"
#include "../node.h"

#ifdef _WIN32
#include <netioapi.h>
#else
#include <net/if.h>
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


typedef struct _WriteRequest {
    DPS_NetConnection* cn;
    uv_write_t writeReq;
    DPS_NetSendComplete onSendComplete;
    struct _WriteRequest* next;
    size_t numBufs;
    uint8_t lenBuf[CBOR_SIZEOF(uint32_t)]; /* pre-allocated buffer for serializing message length */
    uv_buf_t bufs[1];
} WriteRequest;

typedef struct _DPS_NetConnection {
    DPS_Node* node;
    uv_tcp_t socket;
    DPS_NetEndpoint peerEp;
    int refCount;
    uv_shutdown_t shutdownReq;
    /* Rx side */
    uint8_t lenBuf[CBOR_SIZEOF(uint32_t)]; /* pre-allocated buffer for deserializing message length */
    size_t msgLen;  /* size of the message */
    size_t readLen; /* how much data has already been read */
    char* msgBuf;
    /* Tx side */
    uv_connect_t connectReq;
    WriteRequest* pendingWrites;
} DPS_NetConnection;

struct _DPS_NetContext {
    uv_tcp_t socket;   /* the listen socket */
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

#define MIN_BUF_ALLOC_SIZE   512
#define MIN_READ_SIZE        CBOR_SIZEOF(uint32_t)

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;

    if (cn->msgLen) {
        assert(cn->msgBuf);
        buf->len = (uint32_t)(cn->msgLen - cn->readLen);
        buf->base = cn->msgBuf + cn->readLen;
    } else {
        buf->len = sizeof(cn->lenBuf) - cn->readLen;
        buf->base = (char*)(cn->lenBuf + cn->readLen);
    }
}

static void ListenSocketClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed handle %p\n", handle);
    free(handle->data);
}

static void CancelPendingWrites(DPS_NetConnection* cn)
{
    while (cn->pendingWrites) {
        WriteRequest* wr = cn->pendingWrites;
        cn->pendingWrites = wr->next;
        wr->onSendComplete(cn->node, &cn->peerEp, wr->bufs + 1, wr->numBufs - 1, DPS_ERR_NETWORK);
        free(wr);
    }
}

static void StreamClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    /*
     * Free memory for any pending write operations
     */
    CancelPendingWrites(cn);
    DPS_DBGPRINT("Closed stream handle %p\n", handle);
    if (cn->msgBuf) {
        free(cn->msgBuf);
    }
    free(cn);
}

static void OnShutdownComplete(uv_shutdown_t* req, int status)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)req->data;

    DPS_DBGPRINT("Shutdown complete handle %p\n", req->handle);
    CancelPendingWrites(cn);
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
    DPS_Status ret;
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
        netCtx->receiveCB(cn->node, &cn->peerEp, nread == UV_EOF ? DPS_ERR_EOF : DPS_ERR_NETWORK, NULL, 0);
        return;
    }
    assert(socket == (uv_stream_t*)&cn->socket);

    cn->readLen += (uint16_t)nread;
    /*
     * Parse out the message length
     */
    if (!cn->msgLen) {
        DPS_Buffer lenBuf;
        uint32_t msgLen;
        /*
         * Keep reading if we don't have enough data to parse the length
         */
        if (cn->readLen < MIN_READ_SIZE) {
            return;
        }
        assert(cn->readLen == MIN_READ_SIZE);
        DPS_BufferInit(&lenBuf, cn->lenBuf, cn->readLen);
        ret = CBOR_DecodeUint32(&lenBuf, &msgLen);
        if (ret == DPS_OK) {
            cn->msgLen = msgLen;
            cn->msgBuf = malloc(msgLen);
            if (!cn->msgBuf) {
                ret = DPS_ERR_RESOURCES;
            } else {
                /*
                 * Copy message bytes if any
                 */
                cn->readLen = DPS_BufferAvail(&lenBuf);
                memcpy(cn->msgBuf, lenBuf.pos, cn->readLen);
            }
        }
        if (ret == DPS_OK) {
            return;
        }
        /*
         * Report error to receive callback
         */
        netCtx->receiveCB(cn->node, &cn->peerEp, ret, NULL, 0);
    } else {
        /*
         * Keep reading if we don't have a complete message
         */
        if (cn->readLen < cn->msgLen) {
            return;
        }
        DPS_DBGPRINT("Received message of length %zd\n", cn->msgLen);
        ret = netCtx->receiveCB(cn->node, &cn->peerEp, DPS_OK, (uint8_t*)cn->msgBuf, cn->msgLen);
    }
    if (cn->msgBuf) {
        free(cn->msgBuf);
        cn->msgBuf = NULL;
    }
    cn->msgLen = 0;
    cn->readLen = 0;
    /*
     * Stop reading if we got an error
     */
    if (ret != DPS_OK) {
        uv_read_stop(socket);
    }
    /*
     * Shutdown the connection if the upper layer didn't AddRef to keep it alive
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
    int sz = sizeof(cn->peerEp.addr.inaddr);

    DPS_DBGTRACE();

    if (status < 0) {
        DPS_ERRPRINT("OnIncomingConnection %s\n", uv_strerror(status));
        return;
    }
    cn = calloc(1, sizeof(*cn));
    if (!cn) {
        DPS_ERRPRINT("OnIncomingConnection malloc failed\n");
        return;
    }
    ret = uv_tcp_init(stream->loop, &cn->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(cn);
        return;
    }

    cn->node = netCtx->node;
    cn->socket.data = cn;
    cn->peerEp.cn = cn;

    ret = uv_accept(stream, (uv_stream_t*)&cn->socket);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection accept %s\n", uv_strerror(ret));
        return;
    }
    uv_tcp_getpeername((uv_tcp_t*)&cn->socket, (struct sockaddr*)&cn->peerEp.addr.inaddr, &sz);
    ret = uv_read_start((uv_stream_t*)&cn->socket, AllocBuffer, OnData);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection read start %s\n", uv_strerror(ret));
        Shutdown(cn);
    }
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
            uv_interface_address_t* ifsAddrs;
            int numIfs;
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

DPS_NetContext* DPS_NetStart(DPS_Node* node, int port, DPS_OnReceive cb)
{
    int ret;
    DPS_NetContext* netCtx;
    struct sockaddr_in6 addr;

    netCtx = calloc(1, sizeof(*netCtx));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_tcp_init(DPS_GetLoop(node), &netCtx->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->node = node;
    netCtx->receiveCB = cb;
    ret = uv_ip6_addr("::", port, &addr);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_tcp_bind(&netCtx->socket, (const struct sockaddr*)&addr, 0);
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
    return netCtx;

ErrorExit:

    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    netCtx->socket.data = netCtx;
    uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    return NULL;
}

uint16_t DPS_NetGetListenerPort(DPS_NetContext* netCtx)
{
    struct sockaddr_in6 addr;
    int len = sizeof(addr);

    if (!netCtx) {
        return 0;
    }
    if (uv_tcp_getsockname(&netCtx->socket, (struct sockaddr*)&addr, &len)) {
        return 0;
    }
    DPS_DBGPRINT("Listener port = %d\n", ntohs(addr.sin6_port));
    return ntohs(addr.sin6_port);
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    if (netCtx) {
        netCtx->socket.data = netCtx;
        uv_close((uv_handle_t*)&netCtx->socket, ListenSocketClosed);
    }
}

static void OnWriteComplete(uv_write_t* req, int status)
{
    WriteRequest* wr = (WriteRequest*)req->data;
    DPS_Status dpsRet = DPS_OK;

    if (status) {
        DPS_DBGPRINT("OnWriteComplete status=%s\n", uv_err_name(status));
        dpsRet = DPS_ERR_NETWORK;
    }
    wr->onSendComplete(wr->cn->node, &wr->cn->peerEp, wr->bufs + 1, wr->numBufs - 1, dpsRet);
    DPS_NetConnectionDecRef(wr->cn);
    free(wr);
}

static DPS_Status DoWrite(DPS_NetConnection* cn)
{
    int r = 0;

    while (cn->pendingWrites) {
        WriteRequest* wr = cn->pendingWrites;
        wr->writeReq.data = wr;
        r = uv_write(&wr->writeReq, (uv_stream_t*)&cn->socket, wr->bufs, (uint32_t)wr->numBufs, OnWriteComplete);
        if (r != 0) {
            break;
        }
        cn->pendingWrites = wr->next;
        DPS_NetConnectionAddRef(cn);
    }
    if (r) {
        DPS_ERRPRINT("DoWrite - write failed: %s\n", uv_err_name(r));
        return DPS_ERR_NETWORK;
    } else {
        return DPS_OK;
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
        DoWrite(cn);
    } else {
        DPS_ERRPRINT("OnOutgoingConnection - connect %s failed: %s\n", DPS_NodeAddrToString(&cn->peerEp.addr), uv_err_name(status));
        assert(cn->pendingWrites);
        CancelPendingWrites(cn);
    }
}

DPS_Status DPS_NetSend(DPS_Node* node, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_NetSendComplete sendCompleteCB)
{
    DPS_Buffer lenBuf;
    WriteRequest* wr;
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

    wr = malloc(sizeof(WriteRequest) + numBufs * sizeof(uv_buf_t));
    if (!wr) {
        return DPS_ERR_RESOURCES;
    }
    /*
     * Write total message length
     */
    DPS_BufferInit(&lenBuf, wr->lenBuf, sizeof(wr->lenBuf));
    CBOR_EncodeUint32(&lenBuf, len);
    wr->bufs[0].base = (char*)wr->lenBuf;
    wr->bufs[0].len = DPS_BufferUsed(&lenBuf);;
    /*
     * Copy other uvbufs into the write request
     */
    memcpy(wr->bufs + 1, bufs, numBufs * sizeof(uv_buf_t));
    wr->numBufs = numBufs + 1;
    wr->onSendComplete = sendCompleteCB;
    wr->next = NULL;
    /*
     * See if we already have a connection
     */
    if (ep->cn) {
        wr->cn = ep->cn;
        /*
         * If there are pending writes the connection is not up yet
         */
        if (ep->cn->pendingWrites) {
            WriteRequest* last = ep->cn->pendingWrites;
            while (last->next) {
                last = last->next;
            }
            last->next = wr;
            return DPS_OK;
        }
        ep->cn->pendingWrites = wr;
        return DoWrite(ep->cn);
    }
    ep->cn = calloc(1, sizeof(DPS_NetConnection));
    if (!ep->cn) {
        goto ErrExit;
    }
    r = uv_tcp_init(DPS_GetLoop(node), &ep->cn->socket);
    if (r) {
        goto ErrExit;
    }
    ep->cn->peerEp.addr = ep->addr;
    ep->cn->node = node;
    socket = (uv_handle_t*)&ep->cn->socket;

    if (ep->addr.inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)&ep->addr.inaddr;
        if (!in6->sin6_scope_id) {
            in6->sin6_scope_id = GetScopeId(in6);
        }
    }
    ep->cn->connectReq.data = ep->cn;
    r = uv_tcp_connect(&ep->cn->connectReq, &ep->cn->socket, (struct sockaddr*)&ep->addr.inaddr, OnOutgoingConnection);
    if (r) {
        DPS_ERRPRINT("uv_tcp_connect %s error=%s\n", DPS_NodeAddrToString(&ep->addr), uv_err_name(r));
        goto ErrExit;
    }
    ep->cn->peerEp.cn = ep->cn;
    ep->cn->pendingWrites = wr;
    wr->cn = ep->cn;
    DPS_NetConnectionAddRef(ep->cn);
    return DPS_OK;

ErrExit:

    if (wr) {
        free(wr);
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

void DPS_NetConnectionAddRef(DPS_NetConnection* cn)
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
