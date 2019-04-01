/**
 * @file
 * Public APIs
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

#ifndef _DPS_H
#define _DPS_H

#include <dps/targets.h>
#include <stdint.h>
#include <stddef.h>
#include <dps/err.h>
#include <dps/keystore.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_TRUE  1 /**< TRUE boolean value */
#define DPS_FALSE 0 /**< FALSE boolean value */

/**
 * Opaque type for a subscription
 */
typedef struct _DPS_Subscription DPS_Subscription;

/**
 * Opaque type for a publication
 */
typedef struct _DPS_Publication DPS_Publication;

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
 * Opaque type for a DPS node
 */
typedef struct _DPS_Node DPS_Node;

/**
  * Create the node
  */
DPS_Node* DPS_CreateNode(const char* separators);

/**
  * Start the node
  */
DPS_Status DPS_Start(DPS_Node* node);

/**
  * Destroy the node
  */
void DPS_DestroyNode(DPS_Node* node);

/**
  * Get the port number the node is listening on
  */
uint16_t DPS_GetPortNumber(DPS_Node* node);

/**
  * Disable DTLS - this should be called before any DTLS connections are established
  */
DPS_Status DPS_DisableDTLS(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif
