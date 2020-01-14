/**
 * @file
 * Send and receive subscription messages
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

#ifndef _SUB_H
#define _SUB_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include <dps/private/node.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation configured maximum number of topic strings in a subscription
 */
#define DPS_MAX_SUB_TOPICS    8

/**
 * Struct to hold the state of a local subscription. We hold the
 * topics so we can provide return the topic list when we get a
 * match. We compute the filter so we can forward to outbound
 * subscribers.
 */
typedef struct _DPS_Subscription {
    DPS_Node* node;                   /**< Node for this subscription */
    void* userData;                   /**< Application provided user data */
    DPS_PublicationHandler handler;   /**< Callback function to be called for a matching publication */
    const char* topics[DPS_MAX_SUB_TOPICS]; /**< Subscription topics */
    size_t numTopics;                 /**< Number of subscription topics */
    DPS_Subscription* next;           /**< Next subscription in list */
} DPS_Subscription;

/**
 * Send a subscription to a remote node
 *
 * @param node    The local node
 * @param dest    The address of the remote node to send the subscriptions to
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_SendSubscription(DPS_Node* node, DPS_NodeAddress* dest);

/**
 * Decode and process a received subscription
 *
 * @param node       The local node
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf);

/**
 * Decode and process a received subscription acknowledgement
 *
 * @param node       The local node
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buf);

#ifdef __cplusplus
}
#endif

#endif
