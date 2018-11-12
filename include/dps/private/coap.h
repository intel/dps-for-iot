/**
 * @file
 * Compose and parse CoAP messages
 */

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

#ifndef _COAP_H
#define _COAP_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_UDP_PORT   5683 /**< CoAP default port number */

#define COAP_MCAST_ALL_NODES_LINK_LOCAL_6   "ff02::fd"    /**< "All CoAP Nodes" IPv6 multicast address */
#define COAP_MCAST_ALL_NODES_LINK_LOCAL_4   "224.0.1.187" /**< "All CoAP Nodes" IPv4 multicast address */

#define COAP_VERSION          1 /**< CoAP protocol version */

/*
 * Message types
 */
#define COAP_TYPE_CONFIRMABLE      0 /**< Confirmable message type */
#define COAP_TYPE_NON_CONFIRMABLE  1 /**< Non-confirmable message type */
#define COAP_TYPE_ACKNOWLEDGEMENT  2 /**< Acknowledgement message type */
#define COAP_TYPE_RESET            3 /**< Reset message type */

/**
 * Compose a code from a class and detail
 */
#define COAP_CODE(class_bits, detail_bits)  (((class_bits) << 5) | ((detail_bits) & 0x1F))

/*
 * Code classes
 */
#define COAP_REQUEST    0 /**< REQUEST class code */
#define COAP_SUCCESS    2 /**< SUCCESS class code */
#define COAP_ERROR      4 /**< CLIENT ERROR class code */
#define COAP_SRV_ERROR  5 /**< SERVER ERROR class code */

/*
 * Detail codes for class REQUEST
 */
#define COAP_GET      1 /**< GET detail code for class REQUEST */
#define COAP_POST     2 /**< POST detail code for class REQUEST */
#define COAP_PUT      3 /**< PUT detail code for class REQUEST */
#define COAP_DELETE   4 /**< DELETE detail code for class REQUEST */

/*
 * Option identifiers
 */
#define COAP_OPT_IF_MATCH         1  /**< If-Match option identifier */
#define COAP_OPT_URI_HOST         3  /**< Uri-Host option identifier */
#define COAP_OPT_URI_PORT         7  /**< Uri-Port option identifier */
#define COAP_OPT_URI_PATH         11 /**< Uri-Path option identifier */
#define COAP_OPT_CONTENT_FORMAT   12 /**< Content-Format option identifier */
#define COAP_OPT_URI_QUERY        15 /**< Uri-Query option identifier */

#define COAP_END_OF_OPTS   0xFF /**< End of options tag */

/*
 * Media types
 */
#define COAP_FORMAT_APPLICATION_CBOR 60 /**< application/cbor media type */

/**
 * A CoAP option
 */
typedef struct {
    uint8_t id;                 /**< Option identifier */
    size_t len;                 /**< Length of option value */
    const uint8_t* val;         /**< Option value */
} CoAP_Option;

#define COAP_MAX_OPTS       4
#define COAP_MAX_TOKEN_LEN  8


/**
 * A parsed CoAP packet
 */
typedef struct {
    uint8_t version;                   /**< CoAP protocol version */
    uint8_t type;                      /**< CoAP message type */
    uint8_t code;                      /**< CoAP class */
    int16_t msgId;                     /**< CoAP message ID */
    CoAP_Option opts[COAP_MAX_OPTS];   /**< CoAP options */
    uint16_t numOpts;                  /**< Number of CoAP options */
    uint8_t token[COAP_MAX_TOKEN_LEN]; /**< CoAP token */
    size_t tokenLen;                   /**< Size of CoAP token */
} CoAP_Parsed;

/**
 * Parse a CoAP packet from the buffer. The parsed contents hold pointer into
 * buffer so the buffer must not be freed until the parsed packet is no longer
 * needed.
 *
 * @param buf       The buffer containing a CoAP packet
 * @param bufLen    The length of the CoAP packet
 * @param coap      Data structure to return the parsed CoAP packet
 * @param payload   Returns the CoAP payload
 *
 * @return  Returns DPS_OK if the packet was successfully parsed or an error
 *          code if the packet was not successfully parsed.
 */
DPS_Status CoAP_Parse(const uint8_t* buf, size_t bufLen, CoAP_Parsed* coap, DPS_RxBuffer* payload);

/**
 * Free resources allocated for a parsed CoAP packet
 *
 * @param coap  A parsed packet.
 */
void CoAP_Free(CoAP_Parsed* coap);

/**
 * Wrap a buffer in a CoAP envelope.
 *
 * @param buf   Buffer to be wrapped
 *
 * @return   Returns DPS_OK if the buffer was wrapped or an error if the operation failed.
 */
DPS_Status CoAP_Wrap(DPS_TxBuffer* buf);

#ifdef __cplusplus
}
#endif

#endif
