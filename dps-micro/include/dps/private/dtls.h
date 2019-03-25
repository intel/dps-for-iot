/**
 * @file
 * Platform indepedent code for DTLS
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

#ifndef _DPS_DTLS_H
#define _DPS_DTLS_H

#include <stdint.h>
#include <dps/err.h>
#include <dps/private/timer.h>
#include <dps/private/network.h>
#include <dps/private/node.h>
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_cookie.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DTLS_DISABLED,
    DTLS_DISCONNECTED,
    DTLS_IN_HANDSHAKE,
    DTLS_CONNECTED
} DTLS_State;

typedef struct _DPS_DTLS {
    /*
     * mbedtls uses different logic for client and server, so keep
     * track of the role in a connection.
     */
    int sslType;
    DTLS_State state;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    /* For server side */
    mbedtls_ssl_cookie_ctx cookieCtx;
    mbedtls_ssl_cache_context cacheCtx;
    int handshake;
    DPS_Timer* timer;
    uint16_t timeout; /* The set timeout value */
    int toCount;      /* Number of timeouts */
} DPS_DTLS;


/**
 * Start the DTLS handshake
 */
DPS_Status DPS_DTLSHandshake(DPS_Node* node, DPS_NodeAddress* addr, int sslType);

/*
 * Send the data in the tx buffer to the secured DTLS endpoint.
 */
DPS_Status DPS_DTLSSend(DPS_Node* node);

/*
 * Called when data has been received and is in the RxBuffer
 */
DPS_Status DPS_DTLSRecv(DPS_Node* node, DPS_NodeAddress* addr, DPS_RxBuffer* rxBuf);


#ifdef __cplusplus
}
#endif

#endif

