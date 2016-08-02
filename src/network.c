#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps_dbg.h>
#include <dps.h>
#include <network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


#define DPS_PORT     3040

#define MAX_READ_LEN   4096
#define MAX_WRITE_LEN  4096
#define MIN_READ_LEN      8

struct _DPS_NetListener {
    uv_tcp_t socket;
    DPS_Node* node;
    DPS_OnReceive receiveCB;
};

typedef struct {
    DPS_Node* node;
    uv_tcp_t socket;
    uint16_t readLen;
    DPS_OnReceive receiveCB;
    uint8_t buffer[MAX_READ_LEN];
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
    DPS_DBGPRINT("Closed handle %d\n", handle);
    free(handle->data);
}

static void OnShutdownComplete(uv_shutdown_t* req, int status)
{
    DPS_DBGPRINT("Shutdown complete handle %d\n", req->handle);
    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        uv_close((uv_handle_t*)req->handle, HandleClosed);
    }
}

static void OnData(uv_stream_t* socket, ssize_t nread, const uv_buf_t* buf)
{
    ssize_t toRead;
    NetReader* reader = (NetReader*)socket->data;
    struct sockaddr_storage sender;
    int sz = sizeof(sender);

    if (nread < 0) {
        if (!uv_is_closing((uv_handle_t*) socket)) {
            uv_close((uv_handle_t*)socket, HandleClosed);
        }
        return;
    }
    uv_tcp_getpeername((uv_tcp_t*)socket, (struct sockaddr*)&sender, &sz);
    reader->readLen += nread;
    while (1) {
        ssize_t toRead = reader->receiveCB(reader->node, (struct sockaddr*)&sender, reader->buffer, reader->readLen);
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
    DPS_NetListener* listener = (DPS_NetListener*)stream->data;
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
    assert(ret == 0);

    reader->node = listener->node;
    reader->receiveCB = listener->receiveCB;
    reader->socket.data = reader;

    ret = uv_accept(stream, (uv_stream_t*)&reader->socket);
    if (ret == 0) {
        ret = uv_read_start((uv_stream_t*)&reader->socket, AllocBuffer, OnData);
    }
    if (ret != 0) {
        DPS_ERRPRINT("OnIncomingConnection %s\n", uv_strerror(ret));
        uv_close((uv_handle_t*)stream, HandleClosed);
    }
}

#define LISTEN_BACKLOG  2

DPS_NetListener* DPS_NetStartListening(DPS_Node* node, int port, DPS_OnReceive cb)
{
    int ret;
    int len;
    DPS_NetListener* listener;
    struct sockaddr_in6 addr;

    listener = calloc(1, sizeof(*listener));
    if (!listener) {
        return NULL;
    }
    uv_tcp_init(DPS_GetLoop(node), &listener->socket);

    listener->node = node;
    listener->receiveCB = cb;
    ret = uv_ip6_addr("::", port, &addr);
    assert(ret == 0);
    ret = uv_tcp_bind(&listener->socket, (const struct sockaddr*)&addr, 0);
    assert(ret == 0);

    listener->socket.data = listener;
    ret = uv_listen((uv_stream_t*)&listener->socket, LISTEN_BACKLOG, OnIncomingConnection);
    if (ret) {
        DPS_DBGPRINT("Listen error %s\n", uv_strerror(ret));
        uv_close((uv_handle_t*)&listener->socket, HandleClosed);
        return NULL;
    }
    return listener;
}

uint16_t DPS_NetGetListenerPort(DPS_NetListener* listener)
{
    int ret;
    struct sockaddr_in6 addr;
    int len = sizeof(addr);

    if (!listener) {
        return 0;
    }
    ret = uv_tcp_getsockname(&listener->socket, (struct sockaddr*)&addr, &len);
    assert(ret == 0);
    DPS_DBGPRINT("Listener port = %d\n", ntohs(addr.sin6_port));
    return ntohs(addr.sin6_port);
}

void DPS_NetStopListening(DPS_NetListener* listener)
{
    if (listener) {
        uv_close((uv_handle_t*)&listener->socket, HandleClosed);
    }
}

#define MAX_BUFS 3

typedef struct {
    DPS_Node* node;
    struct sockaddr_in6 addr;
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
    writer->onSendComplete(writer->node, (struct sockaddr*)&writer->addr, writer->bufs, writer->numBufs, dpsRet);
    uv_shutdown(&writer->shutdownReq, (uv_stream_t*)req->handle, OnShutdownComplete);
}

static void OnOutgoingConnection(uv_connect_t *req, int status)
{
    int ret;
    NetWriter* writer = (NetWriter*)req->data;

    if (status == 0) {
        /*
         * We need pointers to the writer struct
         */
        writer->writeReq.data = writer;
        writer->socket.data = writer;

        status = uv_write(&writer->writeReq, (uv_stream_t*)&writer->socket, writer->bufs, writer->numBufs, OnWriteComplete);
        if (status != 0) {
            DPS_ERRPRINT("OnOutgoingConnection - write failed: %s\n", uv_err_name(status));
        }
    } else {
        DPS_ERRPRINT("OnOutgoingConnection - connect failed: %s\n", uv_err_name(status));
    }
    if (status != 0) {
        writer->onSendComplete(writer->node, (struct sockaddr*)&writer->addr, writer->bufs, writer->numBufs, DPS_ERR_NETWORK);
        uv_close((uv_handle_t*)&writer->socket, HandleClosed);
    }
}

DPS_Status DPS_NetSend(DPS_Node* node, uv_buf_t* bufs, size_t numBufs, const struct sockaddr* addr, DPS_NetSendComplete sendCompleteCB)
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
    DPS_DBGPRINT("DPS_NetSend total %d bytes to %s/%d\n", len, DPS_NetAddrText(addr), ntohs(((const struct sockaddr_in6*)(addr))->sin6_port));

    writer = calloc(1, sizeof(*writer));
    if (!writer) {
        return DPS_ERR_RESOURCES;
    }
    writer->node = node;
    memcpy(writer->bufs, bufs, numBufs * sizeof(uv_buf_t));
    writer->numBufs = numBufs;
    writer->onSendComplete = sendCompleteCB;
    writer->connectReq.data = writer;
    writer->socket.data = writer;
    memcpy(&writer->addr, addr, sizeof(writer->addr));

    ret = uv_tcp_init(DPS_GetLoop(node), &writer->socket);
    assert(ret == 0);
    ret = uv_tcp_connect(&writer->connectReq, &writer->socket, addr, OnOutgoingConnection);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_connect error=%s\n", uv_err_name(ret));
        uv_close((uv_handle_t*)&writer->socket, HandleClosed);
        return DPS_ERR_NETWORK;
    }
    return DPS_OK;
}

const char* DPS_NetAddrText(const struct sockaddr* addr)
{
    if (addr) {
        static char txt[INET6_ADDRSTRLEN + 8];
        int ret;
        if (addr->sa_family == AF_INET6) {
            ret = uv_ip6_name((const struct sockaddr_in6*)addr, txt, sizeof(txt));
        } else {
            ret = uv_ip4_name((const struct sockaddr_in*)addr, txt, sizeof(txt));
        }
        if (ret) {
            return "Invalid address";
        }
        return txt;
    } else {
        return "NULL";
    }
}

