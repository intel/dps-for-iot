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
#include "node.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Retry limit of sending subscriptions before deleting an
 * unresponsive remote node
 */
#define DPS_MAX_SUBSCRIPTION_RETRIES  8

/**
 * Struct to hold the state of a local subscription. We hold the
 * topics so we can provide return the topic list when we get a
 * match. We compute the filter so we can forward to outbound
 * subscribers.
 */
typedef struct _DPS_Subscription {
    void* userData;                 /**< Application provided user data */
    DPS_BitVector* needs;           /**< Subscription needs */
    DPS_BitVector* bf;              /**< The Bloom filter bit vector for the topics for this subscription */
    DPS_PublicationHandler handler; /**< Callback function to be called for a matching publication */
    DPS_Node* node;                 /**< Node for this subscription */
    DPS_Subscription* next;         /**< Next subscription in list */
    size_t numTopics;               /**< Number of subscription topics */
    char* topics[1];                /**< Subscription topics */
} DPS_Subscription;

/**
 * Free all subscriptions registered with this node
 *
 * @param node  The node for this operation
 */
void DPS_FreeSubscriptions(DPS_Node* node);

/**
 * Send a subscription to a remote node
 *
 * @param node    The local node
 * @param remote  The remote node to send the subscription to
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_SendSubscription(DPS_Node* node, RemoteNode* remote);

/**
 * Decode and process a received subscription
 *
 * @param node       The local node
 * @param ep         The endpoint the subscription was received on
 * @param buffer     The encoded subscription
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscription(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer);

/**
 * Decode and process a received subscription acknowledgement
 *
 * @param node       The local node
 * @param ep         The endpoint the subscription acknowledgement was received on
 * @param buffer     The encoded subscription acknowledgement
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer);

#ifdef __cplusplus
}
#endif

#endif
