/**
 * @file
 * Network layer macros and functions
 */

/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dps/err.h>
#include <dps/dbg.h>
#include <dps/private/dtls.h>
#include <dps/private/node.h>
#include <dps/private/mbedtls.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Controls debug output from the mbedtls library,
 * ranges from 0 (no debug) to 4 (verbose).
 */
#define DEBUG_MBEDTLS_LEVEL 3

/* Personalization string for the DRBG */
static const unsigned char PERSONALIZATION_STRING[] = "DPS_DRBG";

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

static void OnTLSDebug(void *ctx, int level, const char *file, int line, const char *str)
{
    switch (level) {
    case 1:
        DPS_ERRPRINT("%s:%d %s", file, line, str);
        break;
    case 2:
    case 3:
    case 4:
        if (DPS_DEBUG_ENABLED()) {
            DPS_DBGPRINT("%s:%d %s", file, line, str);
        }
        break;
    }
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

static void OnTimeout(DPS_Timer* timer, void* data)
{
    DPS_Node* node = (DPS_Node*)data;
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);

    DPS_DBGTRACE();

    if (++dtls->toCount == 1) {
        DPS_DBGPRINT("intermediate DTLS timeout\n");
        DPS_TimerReset(timer, dtls->timeout);
    } else {
        int ret;
        DPS_ERRPRINT("DTLS timeout - resending\n");
        DPS_TimerCancel(timer);
        dtls->timer = NULL;
        /*
         * Re-do the last handshake step
         */
        ret = mbedtls_ssl_handshake_step(&dtls->ssl);
        if (ret) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                DPS_DBGPRINT("In handshake want read\n");
                ret = 0;
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                DPS_DBGPRINT("In handshake want write\n");
                ret = 0;
            }
            if (ret) {
                DPS_WARNPRINT("Handshake failed - %s\n", TLSErrTxt(ret));
                mbedtls_ssl_session_reset(&dtls->ssl);
                dtls->state = DTLS_DISCONNECTED;
            }
        }
        if (dtls->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
            dtls->state = DTLS_CONNECTED;
            if (DPS_UnicastWritePending(node->network)) {
                assert(dtls->sslType == MBEDTLS_SSL_IS_CLIENT);
                /* Send the packet that was delayed by the DTLS handshake */
                DPS_DTLSSend(node);
            }
        }
    }
}

static void OnTLSTimerSet(void* data, uint32_t int_ms, uint32_t fin_ms)
{
    DPS_Node* node = (DPS_Node*)data;
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);

    DPS_DBGTRACE();
    DPS_DBGPRINT("int_ms=%u,fin_ms=%u\n", int_ms, fin_ms);

    if (!dtls->timer) {
        dtls->toCount = 0;
        dtls->timeout = fin_ms;
        dtls->timer = DPS_TimerSet(int_ms, OnTimeout, node);
    }
    if (fin_ms == 0) {
        DPS_TimerCancel(dtls->timer);
        dtls->timer = NULL;
        return;
    }
}

static int OnTLSTimerGet(void* data)
{
    DPS_Node* node = (DPS_Node*)data;
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);

    DPS_DBGTRACE();

    return dtls->timer ? dtls->toCount : -1;
}

static DPS_Status CAChainResponse(const char* ca, void* data)
{
    DPS_DTLS* dtls = (DPS_DTLS*)data;
    size_t len = ca ? strlen(ca) + 1 : 0;
    int ret;

    DPS_DBGTRACE();

    ret = mbedtls_x509_crt_parse(&dtls->cacert, (const unsigned char*)ca, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing trusted certificate(s) failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status CertResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    DPS_DTLS* dtls = (DPS_DTLS*)data;
    size_t len;
    size_t pwLen;
    int ret;

    DPS_DBGTRACE();

    if (key->type != DPS_KEY_EC_CERT || !key->cert.cert || !key->cert.privateKey) {
        return DPS_ERR_MISSING;
    }
    len = strlen(key->cert.cert) + 1;
    ret = mbedtls_x509_crt_parse(&dtls->cert, key->cert.cert, len);
    if (ret != 0) {
        DPS_WARNPRINT("Parsing certificate failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    len = strlen(key->cert.privateKey) + 1;
    pwLen = key->cert.password ? strlen(key->cert.password) : 0;
    ret =  mbedtls_pk_parse_key(&dtls->pkey, key->cert.privateKey, len, key->cert.password, pwLen);
    if (ret != 0) {
        DPS_WARNPRINT("Parse private key failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static DPS_Status KeyResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    DPS_DTLS* dtls = (DPS_DTLS*)data;
    int ret;

    DPS_DBGTRACE();

    ret = mbedtls_ssl_conf_psk(&dtls->conf, key->symmetric.key, key->symmetric.len, keyId->id, keyId->len);
    if (ret != 0) {
        DPS_WARNPRINT("Set PSK failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static int ResetConnection(DPS_DTLS* dtls, const DPS_NodeAddress* addr)
{
    const char* clientId = DPS_AddrToText(addr);
    int ret;

    DPS_DBGTRACE();

    assert(dtls->sslType == MBEDTLS_SSL_IS_SERVER);

    if (!clientId) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    ret = mbedtls_ssl_session_reset(&dtls->ssl);
    if (ret) {
        DPS_ERRPRINT("Session reset failed: %s\n", TLSErrTxt(ret));
    } else {
        ret = mbedtls_ssl_set_client_transport_id(&dtls->ssl, clientId, strlen(clientId));
        if (ret) {
            DPS_ERRPRINT("Set client transport ID failed: %s\n", TLSErrTxt(ret));
        }
    }
    return ret;
}

DPS_Status DPS_DTLSSend(DPS_Node* node)
{
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);
    size_t len = (LONG)(node->txLen + node->txHdrLen);
    uint8_t* data = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;
    int ret;

    DPS_DBGTRACE();

    do {
        ret = mbedtls_ssl_write(&dtls->ssl, data, len);
        if (ret >= 0 && ret <= len) {
            len -= ret;
            data += ret;
        } else {
            return DPS_ERR_NETWORK;
        }
    } while (len);
    return DPS_OK;
}

DPS_Status DPS_DTLSRecv(DPS_Node* node, const DPS_NodeAddress* addr, DPS_RxBuffer* rxBuf)
{
    DPS_Status status = DPS_OK;
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);
    int ret;

    DPS_DBGTRACE();

    node->rxBuf = rxBuf;

    switch (dtls->state) {
    case DTLS_DISCONNECTED:
        status = DPS_DTLSStartHandshake(node, addr, MBEDTLS_SSL_IS_SERVER);
        /* Let caller know there is no data */
        if (status == DPS_OK) {
            status = DPS_ERR_NO_DATA;
        }
        break;
    case DTLS_CONNECTED:
        assert(dtls->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);
        ret = mbedtls_ssl_read(&dtls->ssl, dtls->tmpBuffer, sizeof(dtls->tmpBuffer));
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                DPS_DBGPRINT("Connection was closed gracefully\n");
                status = DPS_ERR_EOF;
            } else {
                DPS_WARNPRINT("Failed - %s\n", TLSErrTxt(ret));
                status = DPS_ERR_NETWORK;
            }
        } else {
            DPS_DBGPRINT("Decrypted into %d bytes of plaintext\n", ret);
            /* Update the buffer to point to the plaintext data */
            DPS_RxBufferInit(rxBuf, dtls->tmpBuffer, ret);
        }
        break;
    case DTLS_IN_HANDSHAKE:
        /*
         * Run the DTLS handshake for a while
         */
        ret = mbedtls_ssl_handshake(&dtls->ssl);
        if (ret) {
            if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
                DPS_DBGPRINT("In handshake hello verify required\n");
                ret = ResetConnection(dtls, addr);
                if (!ret) {
                    ret = mbedtls_ssl_handshake_step(&dtls->ssl);
                }
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                DPS_DBGPRINT("In handshake want read\n");
                ret = 0;
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                DPS_DBGPRINT("In handshake want write\n");
                ret = 0;
            }
            if (ret) {
                DPS_WARNPRINT("Handshake failed - %s\n", TLSErrTxt(ret));
                dtls->state = DTLS_DISCONNECTED;
                status = DPS_ERR_NETWORK;
            }
        }
        if (dtls->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
            dtls->state = DTLS_CONNECTED;
            if (DPS_UnicastWritePending(node->network)) {
                assert(dtls->sslType == MBEDTLS_SSL_IS_CLIENT);
                /* Send the packet that was delayed by the DTLS handshake */
                status = DPS_DTLSSend(node);
            }
        }
        /* Let caller know there is no data */
        if (status == DPS_OK) {
            status = DPS_ERR_NO_DATA;
        }
        break;
    default:
        status = DPS_ERR_FAILURE;
    }
    return status;
}

static int OnDTLSRecv(void* data, unsigned char *buf, size_t len)
{
    DPS_Node* node = (DPS_Node*)data;
    size_t rxLen = DPS_RxBufferAvail(node->rxBuf);

    DPS_DBGTRACE();

    if (rxLen) {
        if (rxLen > len) {
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        } else {
            memcpy(buf, node->rxBuf->rxPos, rxLen);
            /* Consume all the data in buffer */
            node->rxBuf->rxPos += rxLen;
            return (int)rxLen;
        }
    } else {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
}

static int OnDTLSSend(void* data, const unsigned char *buf, size_t len)
{
    DPS_Status status;
    DPS_Node* node = (DPS_Node*)data;
    DPS_DTLS* dtls = DPS_GetDTLS(node->network);

    DPS_DBGTRACE();

    status = DPS_UnicastWriteAsync(node, node->remoteNode, (void*)buf, len);
    if (status == DPS_OK) {
        return (int)len;
    } else {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
}

static DPS_Status PskResponse(const DPS_Key* key, const DPS_KeyId* keyId, void* data)
{
    mbedtls_ssl_context* ssl = (mbedtls_ssl_context*)data;

    DPS_DBGTRACE();

    int ret = mbedtls_ssl_set_hs_psk(ssl, key->symmetric.key, key->symmetric.len);
    if (ret != 0) {
        DPS_ERRPRINT("Set PSK failed: %s\n", TLSErrTxt(ret));
        return DPS_ERR_MISSING;
    }
    return DPS_OK;
}

static int OnTLSPSKGet(void *data, mbedtls_ssl_context* ssl, const uint8_t* id, size_t idLen)
{
    DPS_Node* node = (DPS_Node*)data;
    DPS_KeyId keyId;
    DPS_Status ret;

    DPS_DBGTRACE();

    if (!node->keyStore || !node->keyStore->keyRequest) {
        DPS_ERRPRINT("Missing key store for PSK\n");
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    if (idLen > DPS_MAX_KEY_ID_LEN) {
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    memcpy(keyId.id, id, idLen);
    keyId.len = idLen;
    ret = node->keyStore->keyRequest(node->keyStore, &keyId, PskResponse, ssl);
    if (ret != DPS_OK) {
        DPS_WARNPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    return 0;
}

DPS_Status DPS_DTLSStartHandshake(DPS_Node* node, const DPS_NodeAddress* addr, int sslType)
{
    DPS_Network* net = node->network;
    DPS_KeyStore* keyStore = node->keyStore;
    int ret;
    const char* ca = NULL;
    const int* ciphersuites = PskCipherSuites;
    DPS_DTLS* dtls = DPS_GetDTLS(net);

    DPS_DBGTRACE();

    if (!keyStore) {
        return DPS_ERR_NULL;
    }

    dtls->sslType = sslType;

    mbedtls_entropy_init(&dtls->entropy);
    mbedtls_ctr_drbg_init(&dtls->drbg);
    mbedtls_ssl_cookie_init(&dtls->cookieCtx);
    mbedtls_ssl_cache_init(&dtls->cacheCtx);
    mbedtls_ssl_config_init(&dtls->conf);
    mbedtls_x509_crt_init(&dtls->cacert);
    mbedtls_x509_crt_init(&dtls->cert);
    mbedtls_pk_init(&dtls->pkey);
    mbedtls_ssl_init(&dtls->ssl);

    ret = mbedtls_ctr_drbg_seed(&dtls->drbg, mbedtls_entropy_func, &dtls->entropy, PERSONALIZATION_STRING, sizeof(PERSONALIZATION_STRING) - 1);
    if (ret != 0) {
        DPS_ERRPRINT("Seeding mbedtls random byte generator failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }
    if (dtls->sslType == MBEDTLS_SSL_IS_SERVER) {
        ret = mbedtls_ssl_cookie_setup(&dtls->cookieCtx, mbedtls_ctr_drbg_random, &dtls->drbg);
        if (ret != 0) {
            DPS_ERRPRINT("Setting up mbedtls cookie context failed: %s\n", TLSErrTxt(ret));
            goto ErrorExit;
        }
    }
    ret = mbedtls_ssl_config_defaults(&dtls->conf, dtls->sslType, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        DPS_ERRPRINT("Setting mbedtls configuration defaults failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }
    mbedtls_ssl_conf_dbg(&dtls->conf, OnTLSDebug, NULL);
    mbedtls_ssl_conf_rng(&dtls->conf, mbedtls_ctr_drbg_random, &dtls->drbg);
    mbedtls_ssl_conf_handshake_timeout(&dtls->conf, MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN, MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX);

    /* Check if we are able to configure cert based authentication or just pre-shared keys */
    if (keyStore->caChainRequest && keyStore->keyRequest) {
        ret = keyStore->caChainRequest(keyStore, CAChainResponse, dtls);
        if (ret == DPS_OK) {
            ret = keyStore->keyRequest(keyStore, &node->signer.kid, CertResponse, dtls);
        }
        if (ret == DPS_OK) {
            mbedtls_ssl_conf_own_cert(&dtls->conf, &dtls->cert, &dtls->pkey);
            ciphersuites = AllCipherSuites;
        }
    }
    if (dtls->sslType == MBEDTLS_SSL_IS_SERVER) {
        mbedtls_ssl_conf_session_cache(&dtls->conf, &dtls->cacheCtx, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
        mbedtls_ssl_conf_dtls_cookies(&dtls->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &dtls->cookieCtx);
        mbedtls_ssl_conf_psk_cb(&dtls->conf, OnTLSPSKGet, node);
    } else if (keyStore->keyAndIdRequest) {
        ret = keyStore->keyAndIdRequest(keyStore, KeyResponse, dtls);
        if (ret != DPS_OK) {
            DPS_WARNPRINT("Get PSK failed: %s\n", DPS_ErrTxt(ret));
        }
    }
    for (const int* cs = ciphersuites; *cs; ++cs) {
        DPS_DBGPRINT("  %s\n", mbedtls_ssl_get_ciphersuite_name(*cs));
    }

    mbedtls_ssl_conf_ciphersuites(&dtls->conf, ciphersuites);
    mbedtls_ssl_conf_authmode(&dtls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_set_bio(&dtls->ssl, node, OnDTLSSend, OnDTLSRecv, NULL);
    mbedtls_ssl_set_timer_cb(&dtls->ssl, node, OnTLSTimerSet, OnTLSTimerGet);

    ret = mbedtls_ssl_setup(&dtls->ssl, &dtls->conf);
    if (ret != 0) {
        DPS_ERRPRINT("Setting up mbedtls ssl context failed: %s\n", TLSErrTxt(ret));
        goto ErrorExit;
    }

    /* Save address of endpoint we are authenticating with */
    DPS_CopyNodeAddress(node->remoteNode, addr);

    if (dtls->sslType == MBEDTLS_SSL_IS_SERVER) {
        ret = ResetConnection(dtls, addr);
        if (ret != 0) {
            DPS_ERRPRINT("Reset connection failed: %s\n", TLSErrTxt(ret));
            goto ErrorExit;
        }
    }
    /*
     * How much debug output do we want?
     */
    mbedtls_debug_set_threshold(DEBUG_MBEDTLS_LEVEL);
    /*
     * Kick off the first step of the DTLS handshake
     */
    ret = mbedtls_ssl_handshake_step(&dtls->ssl);
    if (ret) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            DPS_DBGPRINT("In handshake want read\n");
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            DPS_DBGPRINT("In handshake want write\n");
        } else {
            DPS_WARNPRINT("Handshake failed - %s\n", TLSErrTxt(ret));
            goto ErrorExit;
        }
    }
    dtls->state = DTLS_IN_HANDSHAKE;
    return DPS_OK;

ErrorExit:

    mbedtls_ssl_session_reset(&dtls->ssl);
    return DPS_ERR_NETWORK;
}
