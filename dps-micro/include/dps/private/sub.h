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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation configured maximum number of topic strings in a subscription
 */
#define MAX_SUB_TOPICS    8

/**
 * Struct to hold the state of a local subscription. We hold the
 * topics so we can provide return the topic list when we get a
 * match. We compute the filter so we can forward to outbound
 * subscribers.
 */
typedef struct _DPS_Subscription {
    DPS_Node* node;                 /**< Node for this subscription */
    void* userData;                 /**< Application provided user data */
    DPS_FHBitVector needs;          /**< Subscription needs */
    DPS_BitVector bf;               /**< The Bloom filter bit vector for the topics for this subscription */
    DPS_PublicationHandler handler; /**< Callback function to be called for a matching publication */
    char* topics[MAX_SUB_TOPICS];   /**< Subscription topics */
    size_t numTopics;               /**< Number of subscription topics */
    DPS_Subscription* next;         /**< Next subscription in list */
} DPS_Subscription;

/**
 * Function prototype for a publication handler called when a publication is received that
 * matches a subscription. Note that there is a possibility of false-positive matches.
 *
 * The publication handle is only valid within the body of this callback function.
 * DPS_CopyPublication() will make a partial copy of the publication that can be used later for
 * example to call DPS_AckPublication().
 *
 * The accessor functions DPS_PublicationGetUUID() and DPS_PublicationGetSequenceNum()
 * return information about the received publication.
 *
 * The accessor functions DPS_SubscriptionGetNumTopics() and DPS_SubscriptionGetTopic()
 * return information about the subscription that was matched.
 *
 * @param sub      Opaque handle for the subscription that was matched
 * @param pub      Opaque handle for the publication that was received
 * @param payload  Payload from the publication if any
 * @param len      Length of the payload
 */
typedef void (*DPS_PublicationHandler)(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

/**
 * Allocate memory for a subscription and initialize topics
 *
 * @param node         The DPS node
 * @param sub          The subscription
 * @param topics       The topic strings to match
 * @param numTopics    The number of topic strings to match - must be >= 1
 *
 * @return The newly created subscription or NULL if resources
 *         could not be allocated or the arguments were invalid
 */
DPS_Status* DPS_InitSubscription(DPS_Node* node, DPS_Subscription* sub, const char** topics, size_t numTopics);

/**
 * Store a pointer to application data in a subscription.
 *
 * @param sub   The subscription
 * @param data  The data pointer to store
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetSubscriptionData(DPS_Subscription* sub, void* data);

/**
 * Get application data pointer previously set by DPS_SetSubscriptionData()
 *
 * @param sub   The subscription
 *
 * @return A pointer to the data or NULL if the subscription is invalid
 */
void* DPS_GetSubscriptionData(DPS_Subscription* sub);

/**
 * Send a subscription to a remote node
 *
 * @param node    The local node
 * @param remote  The remote node to send the subscription to
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_SendSubscription(DPS_Subscription* sub);

/**
 * Decode and process a received subscription
 *
 * @param node       The local node
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscription(DPS_Node* node);

/**
 * Decode and process a received subscription acknowledgement
 *
 * @param node       The local node
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeSubscriptionAck(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif
