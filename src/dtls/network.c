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
#include <malloc.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "../node.h"

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_cookie.h"

// NOTES
//
// Before communicating data, DTLS needs to perform a handshake with the
// peer. During this phase DTLS needs retransmission and ordering of
// messages. Besides data and handshake packets, there are also packets
// containing "events" like notification that a peer is going to close.
//
// mbedtls doesn't talk directly to the network, instead it expects client code
// to trigger it's execution once network data is available, then uses a
// callback to read the actual data. Other actions are also implemented with
// callbacks.

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

// Controls debug output from the mbedtls library, ranges from 0 (no debug) to 4 (verbose).
#define DEBUG_MBEDTLS_LEVEL 0

// Personalization string for the DRBG
#define PERSONALIZATION_STRING "DPS_DRBG"

typedef struct _PendingRead {
    uv_buf_t buf;
    struct _PendingRead* next;
} PendingRead;

typedef struct _PendingWrite {
    DPS_NetConnection* cn;
    void* appCtx;
    uv_buf_t* bufs;
    size_t numBufs;
    struct _PendingWrite* next;

    DPS_Status status;
    DPS_NetSendComplete sendCompleteCB;
} PendingWrite;

// DPS_NetConnection holds mbedtls supporting data and any pending reads and
// writes. These pending structures are used for buffering during handshake
// phase, but also to solve some memory lifecycle issues -- ensuring certain
// buffers are alive for enough time.
typedef struct _DPS_NetConnection {
    DPS_Node* node;
    int refCount;

    // Reference to one of existing NetContext sockets (IPv4 or IPv6).
    uv_udp_t* socket;

    DPS_NetEndpoint peer;

    // mbedtls uses different logic for client and server, so keep track of the
    // role in a connection.
    int type;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context randgen;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int handshakeDone;

    // Entries in the read queue are created from data received from the
    // network, and consumed by the callback we give to mbedtls.
    PendingRead* readQueue;

    // Entries in the write queue are created with data we want to send to the
    // network (via DPS_NetSend), and consumed when asking mbedtls to encrypt
    // data.
    PendingWrite* writeQueue;

    // When entries from write queue are consumed, move them to callback queue
    // so that the callback is called later, in an idler without any locks.
    uv_idle_t idleForSendCallbacks;
    PendingWrite* callbackQueue;

    // Keep track of current timeout state for DTLS. mbedtls calls
    // back to set and peek at timer state, but it is up to us call
    // mbedtls when timer triggers.
    uv_timer_t timer;
    int timerStatus;

    // For server connection.
    mbedtls_ssl_cookie_ctx cookieCtx;
    mbedtls_ssl_cache_context cacheCtx;
} DPS_NetConnection;

#define MAX_READ_LEN   4096

struct _DPS_NetContext {
    uv_udp_t rxSocket;
    DPS_Node* node;
    DPS_OnReceive receiveCB;

    // Scratch buffer used to store data read from the network.
    char buffer[MAX_READ_LEN];

    // Scratch buffer used to store the decrypted content.
    char plainBuffer[MAX_READ_LEN];
};

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    DPS_NetContext* netCtx = handle->data;

    DPS_DBGTRACE();
    buf->len = MAX_READ_LEN;
    buf->base = netCtx->buffer;
}

static void mbedtlsDebug(void *ctx, int level, const char *file, int line, const char *str)
{
#ifdef DPS_DEBUG
    if (DPS_DEBUG_ENABLED()) {
        DPS_Log(DPS_LOG_DBGPRINT, file, line, NULL, str);
    }
#endif
}

static bool TLSHandshake(DPS_NetConnection* cn);

//
// TIMER
//
// During handshake mbedtls keep track whether it needs to resend packets. This
// is done by using two callbacks OnTLSTimerSet() and OnTLSTimerGet() used to
// set and peek at the timeout values for a given connection. It is
// responsibility of our code to trigger mbedtls if the timeout has passed.
//

static void OnTLSTimeout(uv_timer_t* timer)
{
    DPS_DBGTRACE();

    DPS_NetConnection* cn = timer->data;

    cn->timerStatus++;
    if (cn->timerStatus == 1) {
        DPS_DBGPRINT("intermediate DTLS timeout\n");
    } else if (cn->timerStatus == 2) {
        DPS_DBGPRINT("final DTLS timeout\n");
        uv_timer_stop(&cn->timer);
        // Timeout is only used for retransmissions during handshake, so when we
        // reach the final timeout, trigger mbedtls to perform a handshake step.
        bool ok = TLSHandshake(cn);
        if (!ok) {
            DPS_LockNode(cn->node);
            RemoteNode* remote;
            remote = DPS_LookupRemoteNode(cn->node, &cn->peer.addr);
            if (remote) {
                DPS_DeleteRemoteNode(cn->node, remote);
                DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&cn->peer.addr));
            }
            DPS_UnlockNode(cn->node);
        }
    }
}

static void OnTLSTimerSet(void* data, uint32_t int_ms, uint32_t fin_ms)
{
    DPS_NetConnection* cn = data;

    uv_timer_stop(&cn->timer);
    if (fin_ms == 0) {
        DPS_DBGPRINT("disabling DTLS timer\n");
        cn->timerStatus = -1;
        return;
    }

    DPS_DBGPRINT("setting DTLS timer to intermediate=%d final=%d\n", int_ms, fin_ms);
    assert(int_ms < fin_ms);

    cn->timerStatus = 0;
    uv_timer_start(&cn->timer, OnTLSTimeout, int_ms, fin_ms - int_ms);
}

static int OnTLSTimerGet(void* data)
{
    DPS_NetConnection* cn = data;

    DPS_DBGPRINT("DTLS timer status is %d\n", cn->timerStatus);
    return cn->timerStatus;
}


//
// DATA TRANSMISSION CALLBACKS
//
// mbedtls uses callbacks to read data from the network and to write data for
// the network. Note that when our code gets new data from the network, it needs
// to trigger mbedtls that will then callback to read the data. Unfortunately
// mbedtls doesn't provide a way to directly feed the data into its state
// machine.
//
// OnTLSRecv() consumes the read queue. OnTLSSend uses uv_udp functions to write
// to the network directly.
//

static int OnTLSRecv(void* data, unsigned char *buf, size_t len)
{
    DPS_DBGTRACE();

    DPS_NetConnection* cn = data;

    DPS_DBGPRINT("OnTLSRecv() want to read using %zu bytes of buffer\n", len);

    PendingRead* pr = cn->readQueue;
    if (!pr) {
        DPS_DBGPRINT("OnTLSRecv() pending read empty\n");
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    DPS_DBGPRINT("OnTLSRecv() using pending read with %zu bytes\n", pr->buf.len);
    cn->readQueue = pr->next;

    if (pr->buf.len > len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    if (pr->buf.len > INT_MAX) {
        /* pr->buf.len will be truncated to an int return value */
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    size_t dataLen = pr->buf.len;
    memcpy_s(buf, pr->buf.len, pr->buf.base, dataLen);

    free(pr->buf.base);
    free(pr);
    return (int) dataLen;
}

typedef struct _SendReq {
    uv_udp_send_t uvReq;
    uv_buf_t buf;
    DPS_Node* node;
    DPS_NodeAddress addr;
} SendReq;

static void OnTLSSendComplete(uv_udp_send_t *req, int status)
{
    SendReq* sendReq = req->data;

    DPS_DBGPRINT("OnTLSSendComplete() cleaning up for sendReq=%p\n", sendReq);
    if (status != 0) {
        DPS_ERRPRINT("ERROR: couldn't send asynchronously with status=%d: %s\n", status, uv_err_name(status));
        DPS_LockNode(sendReq->node);
        RemoteNode* remote;
        remote = DPS_LookupRemoteNode(sendReq->node, &sendReq->addr);
        if (remote) {
            DPS_DeleteRemoteNode(sendReq->node, remote);
            DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&sendReq->addr));
        }
        DPS_UnlockNode(sendReq->node);
    }
    free(sendReq->buf.base);
    free(sendReq);
}

static int OnTLSSend(void* data, const unsigned char *buf, size_t len)
{
    DPS_NetConnection* cn = data;
    SendReq* sendReq = NULL;

    DPS_DBGPRINT("OnTLSSend want to write %zu bytes\n", len);

    if (len > INT_MAX) {
        /* len will be truncated to an int return value */
        goto error;
    }

    sendReq = calloc(1, sizeof(SendReq));
    if (!sendReq) {
        goto error;
    }

    DPS_DBGPRINT("OnTLSSend() created sendReq=%p\n", sendReq);

    // We don't own the buffer mbedtls passed us, need to copy for the UDP request that is async.
    sendReq->buf.base = malloc(len);
    if (!sendReq->buf.base) {
        goto error;
    }

    memcpy_s(sendReq->buf.base, len, buf, len);
#ifdef _WIN32
    /* Under Windows, sendReq->buf.len is a ULONG, not a size_t */
    if (len > ULONG_MAX) {
        goto error;
    }
    sendReq->buf.len = (ULONG) len;
#else
    sendReq->buf.len = len;
#endif
    sendReq->uvReq.data = sendReq;
    sendReq->node = cn->node;
    sendReq->addr = cn->peer.addr;

    struct sockaddr_storage inaddr;
    memcpy_s(&inaddr, sizeof(inaddr), &cn->peer.addr.inaddr, sizeof(cn->peer.addr.inaddr));
    DPS_MapAddrToV6((struct sockaddr *)&inaddr);

    int err = uv_udp_send(&sendReq->uvReq, cn->socket, &sendReq->buf, 1, (const struct sockaddr *)&inaddr, OnTLSSendComplete);
    if (err) {
        DPS_ERRPRINT("ERROR: couldn't send UDP packet: %s\n", uv_err_name(err));
        goto error;
    }

    return (int) len;

error:
    if (sendReq) {
        if (sendReq->buf.base) {
            free(sendReq->buf.base);
        }
        free(sendReq);
    }
    return -1;
}

static void CancelPendingWrites(DPS_NetConnection* cn, PendingWrite* pw)
{
    while (pw) {
        PendingWrite* next = pw->next;
        DPS_DBGPRINT("calling sendComplete callback for PendingWrite=%p [cancel]\n", pw);
        pw->sendCompleteCB(cn->node, pw->appCtx, &cn->peer, pw->bufs, pw->numBufs, DPS_ERR_NETWORK);
        free(pw->bufs);
        free(pw);
        pw = next;
    }
}

static void DestroyConnection(DPS_NetConnection* cn)
{
    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_cookie_free(&cn->cookieCtx);
        mbedtls_ssl_cache_free(&cn->cacheCtx);
    }

    mbedtls_entropy_free(&cn->entropy);
    mbedtls_ctr_drbg_free(&cn->randgen);
    mbedtls_ssl_config_free(&cn->conf);
    mbedtls_ssl_free(&cn->ssl);

    PendingRead* pr = cn->readQueue;
    while (pr) {
        PendingRead* next = pr->next;
        free(pr);
        pr = next;
    }

    CancelPendingWrites(cn, cn->writeQueue);
    CancelPendingWrites(cn, cn->callbackQueue);

    free(cn);
}

static DPS_NetConnection* CreateConnection(DPS_Node* node, const struct sockaddr* addr, int type)
{
    int ret;
    DPS_NetConnection* cn;

    if (type == MBEDTLS_SSL_IS_SERVER) {
        DPS_DBGPRINT("creating a server DTLS context\n");
    } else {
        DPS_DBGPRINT("creating a client DTLS context\n");
    }

    // TODO: Add support for PKI instead (or in addition to) the network key.
    static const unsigned char id[] = "dps";
    static const size_t idLen = sizeof(id);
    uint8_t key[256] = { 0 };
    size_t keyLen = 0;

    DPS_KeyStore* keyStore = node->keyStore;
    if (!keyStore || !keyStore->networkKeyHandler) {
        return NULL;
    }
    ret = keyStore->networkKeyHandler(keyStore, key, sizeof(key), &keyLen);
    if (ret != DPS_OK) {
        return NULL;
    }
    if (keyLen == 0) {
        return NULL;
    }

    cn = calloc(1, sizeof(DPS_NetConnection));
    if (!cn) {
        return NULL;
    }

    cn->node = node;
    cn->type = type;

    uv_timer_init(node->loop, &cn->timer);
    cn->timerStatus = -1;
    cn->timer.data = cn;

    uv_idle_init(DPS_GetLoop(node), &cn->idleForSendCallbacks);
    cn->idleForSendCallbacks.data = cn;

    cn->socket = &node->netCtx->rxSocket;

    mbedtls_ssl_init(&cn->ssl);
    mbedtls_ssl_config_init(&cn->conf);
    mbedtls_ctr_drbg_init(&cn->randgen);

    // The default implementation is in mbedtls_platform_entropy_poll() and will rely on getrandom
    // or /dev/urandom in Linux; and on CryptGenRandom() on Windows.
    mbedtls_entropy_init(&cn->entropy);

    ret = mbedtls_ctr_drbg_seed(&cn->randgen, mbedtls_entropy_func, &cn->entropy,
                                (const unsigned char*)PERSONALIZATION_STRING, sizeof(PERSONALIZATION_STRING));
    if (ret != 0) {
        DPS_ERRPRINT("ERROR: seeding mbedtls random byte generator (%d)\n", ret);
        goto error;
    }

    ret = mbedtls_ssl_config_defaults(&cn->conf, cn->type, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        DPS_ERRPRINT("ERROR: setting mbedtls configuration defaults (%d)\n", ret);
        goto error;
    }

    mbedtls_ssl_conf_dbg(&cn->conf, mbedtlsDebug, NULL);
    mbedtls_ssl_conf_rng(&cn->conf, mbedtls_ctr_drbg_random, &cn->randgen);
    mbedtls_ssl_conf_psk(&cn->conf, key, keyLen, id, idLen);

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_cookie_init(&cn->cookieCtx);
        mbedtls_ssl_cache_init(&cn->cacheCtx);
        mbedtls_ssl_conf_session_cache(&cn->conf, &cn->cacheCtx, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );

        ret = mbedtls_ssl_cookie_setup(&cn->cookieCtx, mbedtls_ctr_drbg_random, &cn->randgen);
        if (ret != 0) {
            DPS_ERRPRINT("ERROR: setting up mbedtls cookie context (%d)\n", ret);
            goto error;
        }

        mbedtls_ssl_conf_dtls_cookies(&cn->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cn->cookieCtx);
    }

    mbedtls_ssl_set_bio(&cn->ssl, cn, OnTLSSend, OnTLSRecv, NULL);
    mbedtls_ssl_set_timer_cb(&cn->ssl, cn, OnTLSTimerSet, OnTLSTimerGet);

    ret = mbedtls_ssl_setup(&cn->ssl, &cn->conf);
    if (ret != 0) {
        DPS_ERRPRINT("ERROR: setting up mbedtls ssl context (%d)\n", ret);
        goto error;
    }

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        char clientID[INET6_ADDRSTRLEN] = { 0 };
        if (addr->sa_family == AF_INET) {
            uv_ip4_name((const struct sockaddr_in*)addr, clientID, sizeof(clientID));
        } else {
            uv_ip6_name((const struct sockaddr_in6*)addr, clientID, sizeof(clientID));
        }
        ret = mbedtls_ssl_set_client_transport_id(&cn->ssl, (const unsigned char*)clientID, strnlen(clientID, sizeof(clientID)));
        if (ret != 0) {
            DPS_ERRPRINT("ERROR: setting client transport id (%d)\n", ret);
            goto error;
        }
    }

    return cn;

error:
    if (ret != 0) {
        char errorBuf[128] = { 0 };
        mbedtls_strerror(ret, errorBuf, sizeof(errorBuf)-1);
        DPS_ERRPRINT("CreateConnection() last mbedtls error was: %d - %s\n\n", ret, errorBuf);
    }

    DestroyConnection(cn);
    return NULL;
}

static void OnIdleForSendCallbacks(uv_idle_t* idle)
{
    DPS_DBGTRACE();

    DPS_NetConnection* cn = (DPS_NetConnection*)idle->data;

    if (!cn->callbackQueue) {
        DPS_DBGPRINT("OnIdleForSendCallbacks() called without anything in the callback queue\n");
    }

    while (cn->callbackQueue) {
        PendingWrite* pw = cn->callbackQueue;
        cn->callbackQueue = pw->next;
        DPS_DBGPRINT("calling sendComplete callback for PendingWrite=%p status=%d\n", pw, pw->status);
        pw->sendCompleteCB(cn->node, pw->appCtx, &cn->peer, pw->bufs, pw->numBufs, pw->status);
        free(pw->bufs);
        free(pw);
    }

    uv_idle_stop(&cn->idleForSendCallbacks);
}

//
// TRIGGERING THE STATE MACHINE
//
// There are three main ways to trigger the mbedtls state machine: ask for
// perform a handshake step, ask it to read data, and ask it to write
// data. Until the handshake is done, just the first action is valid.
//
// The functions below essentially wrap the mbedtls calls adding debugging and
// handling our data structures.
//

static void TLSWrite(DPS_NetConnection* cn)
{
    int ret;
    uint8_t* base;
    DPS_TxBuffer txbuf;
    size_t total;

    PendingWrite* pw = cn->writeQueue;
    if (!pw) {
        DPS_DBGPRINT("TLSWrite() no pending writes\n");
        return;
    }

    cn->writeQueue = pw->next;
    pw->next = NULL;

    {
        PendingWrite* q = cn->callbackQueue;
        if (!q) {
            cn->callbackQueue = pw;
            uv_idle_start(&cn->idleForSendCallbacks, OnIdleForSendCallbacks);
        } else {
            while (q->next) {
                q = q->next;
            }
            q->next = pw;
        }
    }

    DPS_DBGPRINT("TLSWrite() using pending write with %d bufs\n", pw->numBufs);

    if (pw->numBufs == 1) {
        total = pw->bufs[0].len;
        base = (uint8_t*)pw->bufs[0].base;
    } else {
        total = 0;
        for (int i = 0; i < pw->numBufs; i++) {
            total += pw->bufs[i].len;
        }

        // DPS_NetSend follows libuv and let the user send multiple
        // buffers. These are automatically merged together. However mbedtls
        // expects a single buffer.
        ret = DPS_TxBufferInit(&txbuf, NULL, total);
        if (ret != DPS_OK) {
            pw->status = DPS_ERR_RESOURCES;
            return;
        }
        for (int i = 0; i < pw->numBufs; i++) {
            DPS_TxBufferAppend(&txbuf, (uint8_t*)pw->bufs[i].base, pw->bufs[i].len);
        }
        base = txbuf.base;
    }

    DPS_DBGPRINT("TLSWrite() writing %d bytes of plaintext via DTLS\n", total);
    DPS_DBGBYTES(base, total);

    // HERE: there's no data pointer to make a connection between this PendingWrite and whatever we
    // are going to write in the udp socket. Maybe it is implicit that after this call our udp
    // callback was called, so we stitch things together after the call.
    ret = mbedtls_ssl_write(&cn->ssl, base, total);

    if (pw->numBufs != 1) {
        DPS_TxBufferFree(&txbuf);
    }

    // TODO: Need to handle short writes?

    if (ret < 0) {
        DPS_ERRPRINT("TLSWrite() failure when writing to TLS\n");
        pw->status = DPS_ERR_NETWORK;
    }
}

static void TLSRead(DPS_NetConnection* cn)
{
    DPS_NetContext* netCtx = cn->node->netCtx;
    int ret;

    ret = mbedtls_ssl_read(&cn->ssl, (unsigned char*)netCtx->plainBuffer, sizeof(netCtx->plainBuffer)-1);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            DPS_DBGPRINT("TLSRead() connection was closed gracefully\n");
        } else {
            DPS_DBGPRINT("TLSRead() failed, mbedtls_ssl_read returned -0x%x\n\n", -ret);
        }
        DPS_LockNode(cn->node);
        RemoteNode* remote;
        remote = DPS_LookupRemoteNode(cn->node, &cn->peer.addr);
        if (remote) {
            DPS_DeleteRemoteNode(cn->node, remote);
            DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&cn->peer.addr));
        }
        DPS_UnlockNode(cn->node);
    } else {
        DPS_DBGPRINT("TLSRead() decrypted into %d bytes of plaintext\n", ret);
        DPS_DBGBYTES((const uint8_t*)netCtx->plainBuffer, ret);

        ret = netCtx->receiveCB(netCtx->node, &cn->peer, DPS_OK, (uint8_t*)netCtx->plainBuffer, ret);
        if (ret != DPS_OK) {
            /*
             * Release the connection if the upper layer didn't AddRef to keep it alive
             */
            DPS_NetConnectionDecRef(cn);
        }
    }

    memset(netCtx->plainBuffer, 0, sizeof(netCtx->plainBuffer));
}

static bool TLSHandshake(DPS_NetConnection* cn)
{
    DPS_DBGTRACE();

    int ret = mbedtls_ssl_handshake(&cn->ssl);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        DPS_DBGPRINT("TLSHandshake() hello verification required, resetting\n");
        mbedtls_ssl_session_reset(&cn->ssl);

        if (cn->type == MBEDTLS_SSL_IS_SERVER) {
            char clientID[128] = { 0 };
            const struct sockaddr* addr = (const struct sockaddr*)&cn->peer.addr.inaddr;
            if (addr->sa_family == AF_INET) {
                uv_ip4_name((const struct sockaddr_in*)addr, clientID, sizeof(clientID)-1);
            } else {
                uv_ip6_name((const struct sockaddr_in6*)addr, clientID, sizeof(clientID)-1);
            }
            ret = mbedtls_ssl_set_client_transport_id(&cn->ssl, (const unsigned char*)clientID, sizeof(clientID));
            if (ret != 0) {
                DPS_ERRPRINT("ERROR: couldn't set client transport id (%d)\n", ret);
            }
        }

        return true;
    }

    // The two cases below just let us know that handshake is waiting for more
    // data to be sent or received.
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        DPS_DBGPRINT("TLSHandshake() want read\n");
        return true;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        DPS_DBGPRINT("TLSHandshake() want write\n");
        return true;
    }

    if (ret != 0) {
        char buf[256] = { 0 };
        mbedtls_strerror(ret, buf, sizeof(buf)-1);
        DPS_ERRPRINT("TLSHandshake failed: %s\n", buf);
        return false;
    }

    uint32_t verifyFlags = mbedtls_ssl_get_verify_result(&cn->ssl);
    if (verifyFlags != 0) {
        DPS_ERRPRINT("TLSHandshake() failure when getting the verify result\n");
        return false;
    }

    // TODO: Actually verify the peer. Look at this when using PKI.

    // Handshake is done, consume anything pending.
    cn->handshakeDone = 1;
    DPS_DBGPRINT("TLSHandshake() is done\n");
    while (cn->readQueue) {
        TLSRead(cn);
    }
    while (cn->writeQueue) {
        TLSWrite(cn);
    }
    return true;
}

static void OnData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    int ret;
    DPS_NetConnection* cn;
    DPS_NetContext* netCtx = socket->data;

    DPS_DBGTRACE();
    if (nread < 0) {
        DPS_ERRPRINT("OnData error %s\n", uv_err_name((int)nread));
        return;
    }
    if (!nread) {
        return;
    }
    if (!buf) {
        DPS_ERRPRINT("OnData no buffer\n");
        return;
    }
    if (!addr) {
        DPS_ERRPRINT("OnData no address\n");
        return;
    }
#ifdef _WIN32
    /* Under Windows, pr->buf.len is a ULONG, not a size_t */
    if (nread > ULONG_MAX) {
        goto exit;
    }
#endif

    DPS_DBGPRINT("OnData() received %zd bytes from network\n", nread);

    DPS_NodeAddress* nodeAddr = DPS_CreateAddress();
    DPS_SetAddress(nodeAddr, addr);

    DPS_LockNode(netCtx->node);

    // A node stops in two steps. It happens that in the middle of one of these steps we can receive
    // a message, that can trigger the creation of a connection, leading to more messages to be sent to
    // the network.
    if (netCtx->node->state == DPS_NODE_STOPPING) {
        DPS_DBGPRINT("OnData() ignoring data received while stopping the node\n");
        goto exit;
    }

    RemoteNode* remote = DPS_LookupRemoteNode(netCtx->node, nodeAddr);

    if (remote) {
        cn = remote->ep.cn;
        assert(cn);
    } else {
        cn = CreateConnection(netCtx->node, addr, MBEDTLS_SSL_IS_SERVER);
        if (!cn) {
            DPS_ERRPRINT("could not create server connection structure\n");
            goto exit;
        }
        ret = DPS_AddRemoteNode(netCtx->node, nodeAddr, cn, &remote);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("OnData error: Couldn't add remote node\n");
            DestroyConnection(cn);
            goto exit;
        }
        cn->peer = remote->ep;
    }

    DPS_DestroyAddress(nodeAddr);

    // TODO: After the handshake is done, we don't need to use pending structure. It is being used
    // because it is convenient to have one codepath for reading. To improve this must take in
    // consideration that sometimes a connection might be reset (so we need to use pending again).

    PendingRead* pr = calloc(1, sizeof(PendingRead));
    pr->buf = *buf;
    pr->buf.base = calloc(1, nread);
#ifdef _WIN32
    pr->buf.len = (ULONG) nread;
#else
    pr->buf.len = nread;
#endif
    memcpy_s(pr->buf.base, pr->buf.len, buf->base, nread);

    PendingRead* q = cn->readQueue;
    if (!q) {
        cn->readQueue = pr;
    } else {
        while (q->next) {
            q = q->next;
        }
        q->next = pr;
    }

    if (!cn->handshakeDone) {
        bool ok = TLSHandshake(cn);
        if (!ok) {
            DPS_DeleteRemoteNode(cn->node, remote);
            DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&cn->peer.addr));
        }
    } else {
        TLSRead(cn);
    }

 exit:
    DPS_UnlockNode(netCtx->node);
}

static void RxHandleClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed Rx handle %p\n", handle);
    free(handle->data);
}

DPS_NetContext* DPS_NetStart(DPS_Node* node, int port, DPS_OnReceive cb)
{
    int ret;
    DPS_NetContext* netCtx;
    struct sockaddr_storage addr;

    netCtx = calloc(1, sizeof(*netCtx));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_udp_init(DPS_GetLoop(node), &netCtx->rxSocket);
    if (ret) {
        DPS_ERRPRINT("uv_udp_init error=%s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->node = node;
    netCtx->receiveCB = cb;
    ret = uv_ip6_addr("::", port, (struct sockaddr_in6*)&addr);
    if (ret) {
        goto ErrorExit;
    }
    netCtx->rxSocket.data = netCtx;
    ret = uv_udp_bind(&netCtx->rxSocket, (const struct sockaddr*)&addr, 0);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_udp_recv_start(&netCtx->rxSocket, AllocBuffer, OnData);
    if (ret) {
        goto ErrorExit;
    }

    mbedtls_debug_set_threshold(DEBUG_MBEDTLS_LEVEL);

    return netCtx;

ErrorExit:

    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    uv_close((uv_handle_t*)&netCtx->rxSocket, RxHandleClosed);
    return NULL;
}

uint16_t DPS_NetGetListenerPort(DPS_NetContext* netCtx)
{
    struct sockaddr_in6 addr;
    int len = sizeof(addr);

    if (!netCtx) {
        return 0;
    }
    if (uv_udp_getsockname(&netCtx->rxSocket, (struct sockaddr*)&addr, &len)) {
        return 0;
    }
    DPS_DBGPRINT("Listener port = %d\n", ntohs(addr.sin6_port));
    return ntohs(addr.sin6_port);
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    if (netCtx) {
        uv_udp_recv_stop(&netCtx->rxSocket);
        uv_close((uv_handle_t*)&netCtx->rxSocket, RxHandleClosed);
    }
}

static void TimerClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    DestroyConnection(cn);
}

static void IdleForCallbacksClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    uv_close((uv_handle_t*)&cn->timer, TimerClosed);
}

void DPS_NetConnectionDecRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        assert(cn->refCount > 0);
        if (--cn->refCount == 0) {
            uv_idle_stop(&cn->idleForSendCallbacks);
            uv_timer_stop(&cn->timer);
            uv_close((uv_handle_t*)&cn->idleForSendCallbacks, IdleForCallbacksClosed);
        }
    }
}

DPS_Status DPS_NetSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_NetSendComplete sendCompleteCB)
{
    DPS_DBGTRACE();

#ifndef NDEBUG
    {
        size_t i;
        size_t len = 0;
        for (i = 0; i < numBufs; ++i) {
            len += bufs[i].len;
        }
        DPS_DBGPRINT("DPS_NetSend total %zu bytes to %s\n", len, DPS_NodeAddrToString(&ep->addr));
    }
#endif

    DPS_NetConnection* cn;

    if (!ep->cn) {
        ep->cn = CreateConnection(node, (const struct sockaddr*)&ep->addr.inaddr, MBEDTLS_SSL_IS_CLIENT);
        if (!ep->cn) {
            return DPS_ERR_RESOURCES;
        }
        ep->cn->peer = *ep;
        DPS_NetConnectionAddRef(ep->cn);
    }

    cn = ep->cn;

    PendingWrite* pw = calloc(1, sizeof(PendingWrite));
    if (!pw) {
        return DPS_ERR_RESOURCES;
    }
    pw->cn = cn;
    pw->appCtx = appCtx;
    pw->bufs = calloc(numBufs, sizeof(uv_buf_t));
    if (!pw->bufs) {
        free(pw);
        return DPS_ERR_RESOURCES;
    }

    memcpy_s(pw->bufs, numBufs * sizeof(uv_buf_t), bufs, numBufs * sizeof(uv_buf_t));
    pw->numBufs = numBufs;
    pw->sendCompleteCB = sendCompleteCB;

    PendingWrite* q = cn->writeQueue;
    if (!q) {
        cn->writeQueue = pw;
    } else {
        while (q->next) {
            q = q->next;
        }
        q->next = pw;
    }

    if (!cn->handshakeDone) {
        bool ok = TLSHandshake(cn);
        if (!ok) {
            DPS_LockNode(cn->node);
            RemoteNode* remote;
            remote = DPS_LookupRemoteNode(cn->node, &cn->peer.addr);
            if (remote) {
                DPS_DeleteRemoteNode(cn->node, remote);
                DPS_DBGPRINT("Removed node %s\n", DPS_NodeAddrToString(&cn->peer.addr));
            }
            DPS_UnlockNode(cn->node);
        }
    } else {
        TLSWrite(cn);
    }

    return DPS_OK;
}

void DPS_NetConnectionAddRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        ++cn->refCount;
    }
}
