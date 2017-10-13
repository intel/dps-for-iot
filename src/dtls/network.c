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

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;

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

    DPS_NetConnection* next;
} DPS_NetConnection;

#define MAX_READ_LEN   4096

struct _DPS_NetContext {
    uv_udp_t rxSocket;
    DPS_Node* node;
    DPS_OnReceive receiveCB;
    DPS_NetConnection* cns;

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

static DPS_NetConnection* LookupConnection(DPS_NetContext* netCtx, DPS_NodeAddress* addr)
{
    DPS_NetConnection* cn;

    for (cn = netCtx->cns; cn != NULL; cn = cn->next) {
        if (DPS_SameAddr(&cn->peer.addr, addr)) {
            return cn;
        }
    }
    return NULL;
}

static char errBuf[256] = { 0 };

static const char *TLSErrTxt(int ret)
{
    mbedtls_strerror(ret, errBuf, sizeof(errBuf));
    return errBuf;
}

static const char *TLSVerifyTxt(uint32_t flags)
{
    // We don't provide a prefix
    mbedtls_x509_crt_verify_info(errBuf, sizeof(errBuf), "", flags);
    return errBuf;
}

static void OnTLSDebug(void *ctx, int level, const char *file, int line, const char *str)
{
#ifdef DPS_DEBUG
    if (DPS_DEBUG_ENABLED()) {
        DPS_Log(DPS_LOG_DBGPRINT, file, line, NULL, "%s", str);
    }
#endif
}

static void DestroyConnection(DPS_NetConnection* cn);
static bool TLSHandshake(DPS_NetConnection* cn);

//
// PSK
//

static DPS_Status TLSPSKSet(DPS_KeyStoreRequest* request, const unsigned char* key, size_t len)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_ssl_set_hs_psk(&cn->ssl, key, len);
    if (ret != 0) {
        DPS_ERRPRINT("Set PSK failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static int OnTLSPSKGet(void *data, mbedtls_ssl_context* ssl, const unsigned char* id, size_t idLen)
{
    DPS_NetConnection* cn = data;
    DPS_KeyStore* keyStore = cn->node->keyStore;
    DPS_KeyStoreRequest request;
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!keyStore || !keyStore->keyHandler) {
        DPS_ERRPRINT("Missing key store for PSK\n");
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    request.keyStore = keyStore;
    request.data = cn;
    request.setKey = TLSPSKSet;
    ret = keyStore->keyHandler(&request, id, idLen);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    return 0;
}

//
// TIMER
//
// During handshake mbedtls keep track whether it needs to resend packets. This
// is done by using two callbacks OnTLSTimerSet() and OnTLSTimerGet() used to
// set and peek at the timeout values for a given connection. It is
// responsibility of our code to trigger mbedtls if the timeout has passed.
//

static void OnTimeout(uv_timer_t* timer)
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
            DestroyConnection(cn);
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
    uv_timer_start(&cn->timer, OnTimeout, int_ms, fin_ms - int_ms);
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
    DPS_NetConnection* cn = data;

    DPS_DBGTRACEA("len=%d,addr=%s\n", len, DPS_NodeAddrToString(&cn->peer.addr));

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
    DPS_NetConnection* cn;
} SendReq;

static void OnSendComplete(uv_udp_send_t *req, int status)
{
    SendReq* sendReq = req->data;

    DPS_DBGPRINT("OnSendComplete() cleaning up for sendReq=%p\n", sendReq);
    if (status != 0) {
        DPS_ERRPRINT("Send failed: %s\n", uv_err_name(status));
    }
    free(sendReq->buf.base);
    free(sendReq);
}

static int OnTLSSend(void* data, const unsigned char *buf, size_t len)
{
    DPS_NetConnection* cn = data;
    SendReq* sendReq = NULL;

    DPS_DBGTRACEA("len=%d,addr=%s\n", len, DPS_NodeAddrToString(&cn->peer.addr));

    if (len > INT_MAX) {
        /* len will be truncated to an int return value */
        goto ErrorExit;
    }

    sendReq = calloc(1, sizeof(SendReq));
    if (!sendReq) {
        goto ErrorExit;
    }

    DPS_DBGPRINT("OnTLSSend() created sendReq=%p\n", sendReq);

    // We don't own the buffer mbedtls passed us, need to copy for the UDP request that is async.
    sendReq->buf.base = malloc(len);
    if (!sendReq->buf.base) {
        goto ErrorExit;
    }

    memcpy_s(sendReq->buf.base, len, buf, len);
#ifdef _WIN32
    /* Under Windows, sendReq->buf.len is a ULONG, not a size_t */
    if (len > ULONG_MAX) {
        goto ErrorExit;
    }
    sendReq->buf.len = (ULONG) len;
#else
    sendReq->buf.len = len;
#endif
    sendReq->uvReq.data = sendReq;
    sendReq->cn = cn;

    struct sockaddr_storage inaddr;
    memcpy_s(&inaddr, sizeof(inaddr), &cn->peer.addr.inaddr, sizeof(cn->peer.addr.inaddr));
    DPS_MapAddrToV6((struct sockaddr *)&inaddr);

    int err = uv_udp_send(&sendReq->uvReq, cn->socket, &sendReq->buf, 1, (const struct sockaddr *)&inaddr, OnSendComplete);
    if (err) {
        DPS_ERRPRINT("Send failed: %s\n", uv_err_name(err));
        goto ErrorExit;
    }

    return (int) len;

 ErrorExit:
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
        DPS_NetConnectionDecRef(cn);
        free(pw->bufs);
        free(pw);
        pw = next;
    }
}

static void CloseConnection(DPS_NetConnection* cn)
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
}

static void TimerClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;

    CloseConnection(cn);

    PendingRead* pr = cn->readQueue;
    while (pr) {
        PendingRead* next = pr->next;
        free(pr);
        pr = next;
    }

    CancelPendingWrites(cn, cn->writeQueue);
    CancelPendingWrites(cn, cn->callbackQueue);

    if (cn->node->netCtx) {
        DPS_NetConnection* next = cn->next;
        if (cn->node->netCtx->cns == cn) {
            cn->node->netCtx->cns = next;
        } else if (cn->node->netCtx->cns) {
            DPS_NetConnection* prev = cn->node->netCtx->cns;
            while (prev->next != cn) {
                prev = prev->next;
                assert(prev);
            }
            prev->next = next;
        }
    }

    free(cn);
}

static void IdleForCallbacksClosed(uv_handle_t* handle)
{
    DPS_NetConnection* cn = (DPS_NetConnection*)handle->data;
    uv_close((uv_handle_t*)&cn->timer, TimerClosed);
}

static void DestroyConnection(DPS_NetConnection* cn)
{
    DPS_DBGTRACE();

    assert(cn->refCount == 0);

    uv_idle_stop(&cn->idleForSendCallbacks);
    uv_timer_stop(&cn->timer);
    uv_close((uv_handle_t*)&cn->idleForSendCallbacks, IdleForCallbacksClosed);
}

static int ResetConnection(DPS_NetConnection* cn, const struct sockaddr* addr)
{
    char clientID[INET6_ADDRSTRLEN] = { 0 };

    /* Only called for servers with cookies enabled */
    assert(cn->type == MBEDTLS_SSL_IS_SERVER);

    mbedtls_ssl_session_reset(&cn->ssl);
    if (addr->sa_family == AF_INET) {
        uv_ip4_name((const struct sockaddr_in*)addr, clientID, sizeof(clientID));
    } else {
        uv_ip6_name((const struct sockaddr_in6*)addr, clientID, sizeof(clientID));
    }
    return mbedtls_ssl_set_client_transport_id(&cn->ssl, (const unsigned char*)clientID, strnlen(clientID, sizeof(clientID)));
}

static DPS_Status SetCA(DPS_KeyStoreRequest* request, const unsigned char* ca, size_t len)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_x509_crt_parse(&cn->cacert, ca, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing trusted certificate(s) failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status SetCert(DPS_KeyStoreRequest* request, const unsigned char* cert, size_t certLen, const unsigned char* key, size_t keyLen,
                          const unsigned char* pwd, size_t pwdLen)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_x509_crt_parse(&cn->cert, cert, certLen);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing certificate failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    ret =  mbedtls_pk_parse_key(&cn->pkey, key, keyLen, pwd, pwdLen);
    if (ret != 0) {
        DPS_WARNPRINT("Parse private key failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status SetKeyAndIdentity(DPS_KeyStoreRequest* request, const unsigned char* key, size_t keyLen, const unsigned char* id, size_t idLen)
{
    DPS_NetConnection* cn = request->data;
    int ret = mbedtls_ssl_conf_psk(&cn->conf, key, keyLen, id, idLen);
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

    DPS_DBGPRINT("CreateConnection() creating a %s DTLS context\n",
                 (type == MBEDTLS_SSL_IS_SERVER) ? "server" : "client");

    if (!keyStore || !keyStore->keyAndIdentityHandler) {
        DPS_ERRPRINT("Missing key store for PSK\n");
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

    cn->socket = &netCtx->rxSocket;

    mbedtls_entropy_init(&cn->entropy);

    // The default implementation is in mbedtls_platform_entropy_poll() and will rely on getrandom
    // or /dev/urandom in Linux; and on CryptGenRandom() on Windows.
    mbedtls_ctr_drbg_init(&cn->drbg);
    ret = mbedtls_ctr_drbg_seed(&cn->drbg, mbedtls_entropy_func, &cn->entropy,
                                (const unsigned char*)PERSONALIZATION_STRING, sizeof(PERSONALIZATION_STRING));
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

    request.keyStore = keyStore;
    request.data = cn;

    mbedtls_x509_crt_init(&cn->cacert);
    request.setCA = SetCA;
    ret = keyStore->caHandler(&request);
    if (ret == 0) {
        mbedtls_ssl_conf_ca_chain(&cn->conf, &cn->cacert, NULL);
    } else {
        DPS_WARNPRINT("Parsing trusted certificate(s) failed: %s\n", DPS_ErrTxt(ret));
    }
    mbedtls_x509_crt_init(&cn->cert);
    mbedtls_pk_init(&cn->pkey);
    request.setCert = SetCert;
    ret = keyStore->certHandler(&request);
    if (ret == 0) {
        mbedtls_ssl_conf_own_cert(&cn->conf, &cn->cert, &cn->pkey);
    } else {
        DPS_WARNPRINT("Parsing certificate failed: %s\n", DPS_ErrTxt(ret));
    }

    if (cn->type == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_conf_session_cache(&cn->conf, &cn->cacheCtx, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
        mbedtls_ssl_conf_dtls_cookies(&cn->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cn->cookieCtx);
        mbedtls_ssl_conf_psk_cb(&cn->conf, OnTLSPSKGet, cn);
    } else {
        request.setKeyAndIdentity = SetKeyAndIdentity;
        ret = keyStore->keyAndIdentityHandler(&request);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
            goto ErrorExit;
        }
    }
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
    return cn;

 ErrorExit:
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
        DPS_NetConnectionDecRef(cn);
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

static void TLSSend(DPS_NetConnection* cn)
{
    int ret;
    uint8_t* base;
    DPS_TxBuffer txbuf;
    size_t total;

    PendingWrite* pw = cn->writeQueue;
    if (!pw) {
        DPS_DBGPRINT("TLSSend() no pending writes\n");
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
        DPS_NetConnectionAddRef(cn);
    }

    DPS_DBGPRINT("TLSSend() using pending write with %d bufs\n", pw->numBufs);

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

    DPS_DBGPRINT("TLSSend() writing %d bytes of plaintext via DTLS\n", total);
    DPS_DBGBYTES(base, total);

    // HERE: there's no data pointer to make a connection between this PendingWrite and whatever we
    // are going to write in the udp socket. Maybe it is implicit that after this call our udp
    // callback was called, so we stitch things together after the call.
    ret = 0;
    do {
        base = base + ret;
        total = total - ret;
        ret = mbedtls_ssl_write(&cn->ssl, base, total);
    } while (0 < ret && ret < total);

    if (pw->numBufs != 1) {
        DPS_TxBufferFree(&txbuf);
    }

    if (ret < 0) {
        DPS_ERRPRINT("TLS write failed: %s\n", TLSErrTxt(ret));
        pw->status = DPS_ERR_NETWORK;
    }
}

static void TLSRecv(DPS_NetConnection* cn)
{
    DPS_NetContext* netCtx = cn->node->netCtx;
    int ret;

    ret = mbedtls_ssl_read(&cn->ssl, (unsigned char*)netCtx->plainBuffer, sizeof(netCtx->plainBuffer)-1);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            DPS_DBGPRINT("TLSRecv() connection was closed gracefully\n");
        } else {
            DPS_DBGPRINT("TLSRecv() failed, mbedtls_ssl_read returned -0x%x\n\n", -ret);
        }
    } else {
        DPS_DBGPRINT("TLSRecv() decrypted into %d bytes of plaintext\n", ret);
        DPS_DBGBYTES((const uint8_t*)netCtx->plainBuffer, ret);

        ret = netCtx->receiveCB(netCtx->node, &cn->peer, DPS_OK, (uint8_t*)netCtx->plainBuffer, ret);
        /*
         * Release the connection if the upper layer didn't AddRef to keep it alive
         */
        if (cn->refCount == 0) {
            DestroyConnection(cn);
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
        ret = ResetConnection(cn, (const struct sockaddr*)&cn->peer.addr.inaddr);
        if (ret != 0) {
            DPS_ERRPRINT("Reset connection failed: %s\n", TLSErrTxt(ret));
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
        DPS_WARNPRINT("TLSHandshake failed: %s\n", TLSErrTxt(ret));
        return false;
    }

    uint32_t verifyFlags = mbedtls_ssl_get_verify_result(&cn->ssl);
    if (verifyFlags == 0) {
        DPS_DBGPRINT("Peer verification succeeded\n");
    } else if (verifyFlags & MBEDTLS_X509_BADCERT_SKIP_VERIFY) {
        DPS_WARNPRINT("Peer verification skipped\n");
    } else {
        DPS_ERRPRINT("Peer verification failed - %s", TLSVerifyTxt(verifyFlags));
    }

    // Handshake is done, consume anything pending.
    cn->handshakeDone = 1;
    DPS_DBGPRINT("TLSHandshake() is done\n");
    while (cn->readQueue) {
        TLSRecv(cn);
    }
    while (cn->writeQueue) {
        TLSSend(cn);
    }
    return true;
}

static void OnData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_NetConnection* cn;
    DPS_NetContext* netCtx = socket->data;

    DPS_DBGTRACEA("nread=%d,addr=%s\n", nread, DPS_NetAddrText(addr));
    if (nread < 0) {
        DPS_ERRPRINT("OnData error: %s\n", uv_err_name((int)nread));
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
        goto Exit;
    }
#endif

    DPS_DBGPRINT("OnData() received %zd bytes from network\n", nread);

    DPS_NodeAddress* nodeAddr = DPS_CreateAddress();
    DPS_SetAddress(nodeAddr, addr);

    // A node stops in two steps. It happens that in the middle of one of these steps we can receive
    // a message, that can trigger the creation of a connection, leading to more messages to be sent to
    // the network.
    if (netCtx->node->state == DPS_NODE_STOPPING) {
        DPS_DBGPRINT("OnData() ignoring data received while stopping the node\n");
        goto Exit;
    }

    cn = LookupConnection(netCtx, nodeAddr);
    if (!cn) {
        cn = CreateConnection(netCtx->node, addr, MBEDTLS_SSL_IS_SERVER);
        if (!cn) {
            DPS_ERRPRINT("Create server connection structure failed\n");
            goto Exit;
        }
        cn->peer.addr = *nodeAddr;
        cn->peer.cn = cn;
    }

    // After the handshake is done, we don't need to use pending structure. It is being used
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
            DestroyConnection(cn);
        }
    } else {
        TLSRecv(cn);
    }

 Exit:
    DPS_DestroyAddress(nodeAddr);
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

    DPS_DBGTRACE();

    netCtx = calloc(1, sizeof(*netCtx));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_udp_init(DPS_GetLoop(node), &netCtx->rxSocket);
    if (ret) {
        DPS_ERRPRINT("UDP init failed: %s\n", uv_err_name(ret));
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
    /* Enable this block to log the supported ciphersuites */
#if 0
    for (const int* cs = mbedtls_ssl_list_ciphersuites(); *cs; ++cs) {
        DPS_DBGPRINT("  %s\n", mbedtls_ssl_get_ciphersuite_name(*cs));
    }
#endif

    return netCtx;

ErrorExit:
    DPS_ERRPRINT("Net start failed: %s\n", uv_err_name(ret));
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
    DPS_DBGTRACE();

    if (netCtx) {
        uv_udp_recv_stop(&netCtx->rxSocket);
        uv_close((uv_handle_t*)&netCtx->rxSocket, RxHandleClosed);
    }
}

void DPS_NetConnectionDecRef(DPS_NetConnection* cn)
{
    if (cn) {
        DPS_DBGTRACE();
        assert(cn->refCount > 0);
        if (--cn->refCount == 0) {
            DestroyConnection(cn);
        }
    }
}

DPS_Status DPS_NetSend(DPS_Node* node, void* appCtx, DPS_NetEndpoint* ep, uv_buf_t* bufs, size_t numBufs, DPS_NetSendComplete sendCompleteCB)
{
    PendingWrite* pw;

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

    pw = calloc(1, sizeof(PendingWrite));
    if (!pw) {
        return DPS_ERR_RESOURCES;
    }
    pw->appCtx = appCtx;
    pw->bufs = calloc(numBufs, sizeof(uv_buf_t));
    if (!pw->bufs) {
        free(pw);
        return DPS_ERR_RESOURCES;
    }
    memcpy_s(pw->bufs, numBufs * sizeof(uv_buf_t), bufs, numBufs * sizeof(uv_buf_t));
    pw->numBufs = numBufs;
    pw->sendCompleteCB = sendCompleteCB;

    if (ep->cn) {
        pw->cn = ep->cn;
        if (ep->cn->writeQueue) {
            PendingWrite* last = ep->cn->writeQueue;
            while (last->next) {
                last = last->next;
            }
            last->next = pw;
            return DPS_OK;
        }
        ep->cn->writeQueue = pw;
        if (ep->cn->handshakeDone) {
            TLSSend(ep->cn);
        }
        return DPS_OK;
    }
    ep->cn = CreateConnection(node, (const struct sockaddr*)&ep->addr.inaddr, MBEDTLS_SSL_IS_CLIENT);
    if (!ep->cn) {
        goto ErrorExit;
    }
    ep->cn->peer = *ep;
    pw->cn = ep->cn;
    ep->cn->writeQueue = pw;
    pw = NULL;
    if (!TLSHandshake(ep->cn)) {
        goto ErrorExit;
    }
    DPS_NetConnectionAddRef(ep->cn);
    return DPS_OK;

 ErrorExit:
    if (pw) {
        if (pw->bufs) {
            free(pw->bufs);
        }
        free(pw);
    }
    DestroyConnection(ep->cn);
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
