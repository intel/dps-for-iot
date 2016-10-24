#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define MAX_READ_LEN   4096
#define MAX_WRITE_LEN  4096
#define MIN_READ_LEN      8

struct _DPS_NetContext {
    uv_tcp_t socket;
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

typedef struct {
    DPS_Node* node;
    uv_tcp_t socket;
    uint16_t readLen;
    DPS_OnReceive receiveCB;
    char buffer[MAX_READ_LEN];
    uv_shutdown_t shutdownReq;
} NetReader;

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    NetReader* reader = (NetReader*)handle->data;

    buf->len = sizeof(reader->buffer) - reader->readLen;
    buf->base = reader->buffer + reader->readLen;
}

static void HandleClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed handle %p\n", handle);
    free(handle->data);
}

static void OnShutdownComplete(uv_shutdown_t* req, int status)
{
    DPS_DBGPRINT("Shutdown complete handle %p\n", req->handle);
    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        uv_close((uv_handle_t*)req->handle, HandleClosed);
    }
}

static void OnData(uv_stream_t* socket, ssize_t nread, const uv_buf_t* buf)
{
    NetReader* reader = (NetReader*)socket->data;
    DPS_NodeAddress sender;
    int sz = sizeof(sender.inaddr);

    if (nread < 0) {
        if (!uv_is_closing((uv_handle_t*) socket)) {
            uv_close((uv_handle_t*)socket, HandleClosed);
        }
        return;
    }
    uv_tcp_getpeername((uv_tcp_t*)socket, (struct sockaddr*)&sender.inaddr, &sz);
    reader->readLen += (uint16_t)nread;
    while (1) {
        ssize_t toRead = reader->receiveCB(reader->node, &sender, (uint8_t*)reader->buffer, reader->readLen);
        if (toRead > 0) {
            break;
        }
        /*
         * If the receiver has nothing more to read or consumed nothing we are done
         */
        if (toRead == 0 || (reader->readLen + toRead) == 0) {
            uv_shutdown(&reader->shutdownReq, socket, OnShutdownComplete);
            break;
        }
        nread = -toRead;
        assert(nread <= sizeof(reader->buffer));
        /*
         * Rebase to the front of the buffer
         */
        memmove(reader->buffer, reader->buffer + nread, nread);
    }
}

static void OnIncomingConnection(uv_stream_t* stream, int status)
{
    int ret;
    DPS_NetContext* netCtx = (DPS_NetContext*)stream->data;
    NetReader* reader;

    DPS_DBGTRACE();

    if (status < 0) {
        DPS_ERRPRINT("OnIncomingConnection %s\n", uv_strerror(status));
        return;
    }
    reader = calloc(1, sizeof(*reader));
    if (!reader) {
        DPS_ERRPRINT("OnIncomingConnection malloc failed\n");
        return;
    }
    ret = uv_tcp_init(stream->loop, &reader->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(reader);
        return;
    }

    reader->node = netCtx->node;
    reader->receiveCB = netCtx->receiveCB;
    reader->socket.data = reader;

    ret = uv_accept(stream, (uv_stream_t*)&reader->socket);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection accept %s\n", uv_strerror(ret));
        uv_close((uv_handle_t*)stream, HandleClosed);
        return;
    }
    ret = uv_read_start((uv_stream_t*)&reader->socket, AllocBuffer, OnData);
    if (ret) {
        DPS_ERRPRINT("OnIncomingConnection read start %s\n", uv_strerror(ret));
        uv_shutdown(&reader->shutdownReq, (uv_stream_t*)&reader->socket, OnShutdownComplete);
        return;
    }
}

static int GetLocalScopeId()
{
    static int localScope = 0;

    if (!localScope) {
        uv_interface_address_t* ifsAddrs;
        int numIfs;
        int i;
        uv_interface_addresses(&ifsAddrs, &numIfs);
        for (i = 0; i < numIfs; ++i) {
            uv_interface_address_t* ifn = &ifsAddrs[i];
            if ((ifn->address.address4.sin_family == AF_INET6) && (strcmp(ifn->name, "lo") == 0)) {
                localScope = i;
            }
        }
        uv_free_interface_addresses(ifsAddrs, numIfs);
    }
    return localScope;
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
    netCtx->socket.data = netCtx;
    ret = uv_ip6_addr("::", port, &addr);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_tcp_bind(&netCtx->socket, (const struct sockaddr*)&addr, 0);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_listen((uv_stream_t*)&netCtx->socket, LISTEN_BACKLOG, OnIncomingConnection);
    if (ret) {
        goto ErrorExit;
    }
    return netCtx;

ErrorExit:

    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    uv_close((uv_handle_t*)&netCtx->socket, HandleClosed);
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
        uv_close((uv_handle_t*)&netCtx->socket, HandleClosed);
    }
}

#define MAX_BUFS 3

typedef struct {
    DPS_Node* node;
    DPS_NodeAddress addr;
    uv_tcp_t socket;
    union {
        uv_connect_t connectReq;
        uv_write_t writeReq;
        uv_shutdown_t shutdownReq;
    };
    uv_buf_t bufs[MAX_BUFS];
    size_t numBufs;
    DPS_NetSendComplete onSendComplete;
} NetWriter;

static void OnWriteComplete(uv_write_t* req, int status)
{
    NetWriter* writer = (NetWriter*)req->data;
    DPS_Status dpsRet = DPS_OK;

    if (status) {
        DPS_ERRPRINT("OnWriteComplete status=%s\n", uv_err_name(status));
        dpsRet = DPS_ERR_NETWORK;
    }
    /*
     * TODO - allow ongoing use of the socket for sending and receiving
     */
    writer->onSendComplete(writer->node, &writer->addr, writer->bufs, writer->numBufs, dpsRet);
    uv_shutdown(&writer->shutdownReq, (uv_stream_t*)req->handle, OnShutdownComplete);
}

static void OnOutgoingConnection(uv_connect_t *req, int status)
{
    NetWriter* writer = (NetWriter*)req->data;

    if (status == 0) {
        /*
         * We need pointers to the writer struct
         */
        writer->writeReq.data = writer;
        writer->socket.data = writer;

        status = uv_write(&writer->writeReq, (uv_stream_t*)&writer->socket, writer->bufs, (uint32_t)writer->numBufs, OnWriteComplete);
        if (status != 0) {
            DPS_ERRPRINT("OnOutgoingConnection - write failed: %s\n", uv_err_name(status));
        }
    } else {
        DPS_ERRPRINT("OnOutgoingConnection - connect %s failed: %s\n", DPS_NetAddrText((struct sockaddr*)&writer->addr), uv_err_name(status));
    }
    if (status != 0) {
        writer->onSendComplete(writer->node, &writer->addr, writer->bufs, (uint32_t)writer->numBufs, DPS_ERR_NETWORK);
        uv_shutdown(&writer->shutdownReq, (uv_stream_t*)req->handle, OnShutdownComplete);
    }
}

DPS_Status DPS_NetSend(DPS_NetContext* netCtx, uv_buf_t* bufs, size_t numBufs, DPS_NodeAddress* addr, DPS_NetSendComplete sendCompleteCB)
{
    int ret;
    NetWriter* writer;
    size_t i;
    size_t len = 0;

    if (numBufs > MAX_BUFS) {
        return DPS_ERR_OVERFLOW;
    }
    for (i = 0; i < numBufs; ++i) {
        len += bufs[i].len;
    }
    if (len > MAX_WRITE_LEN) {
        return DPS_ERR_OVERFLOW;
    }
    DPS_DBGPRINT("DPS_NetSend total %zu bytes to %s\n", len, DPS_NodeAddrToString(addr));

    writer = calloc(1, sizeof(*writer));
    if (!writer) {
        return DPS_ERR_RESOURCES;
    }
    writer->node = netCtx->node;
    memcpy(writer->bufs, bufs, numBufs * sizeof(uv_buf_t));
    writer->numBufs = numBufs;
    writer->onSendComplete = sendCompleteCB;
    writer->connectReq.data = writer;
    writer->socket.data = writer;
    memcpy(&writer->addr, addr, sizeof(writer->addr));

    if (addr->inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)&addr->inaddr;
        if (!in6->sin6_scope_id) {
            in6->sin6_scope_id = GetLocalScopeId();
        }
    }

    ret = uv_tcp_init(DPS_GetLoop(netCtx->node), &writer->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(writer);
        return DPS_ERR_NETWORK;
    }
    ret = uv_tcp_connect(&writer->connectReq, &writer->socket, (struct sockaddr*)&addr->inaddr, OnOutgoingConnection);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_connect %s error=%s\n", DPS_NodeAddrToString(addr), uv_err_name(ret));
        uv_close((uv_handle_t*)&writer->socket, HandleClosed);
        return DPS_ERR_NETWORK;
    }
    return DPS_OK;
}
