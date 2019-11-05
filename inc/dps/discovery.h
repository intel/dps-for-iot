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

#ifndef _DPS_DISCOVERY_H
#define _DPS_DISCOVERY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dps/dps.h>

/**
 * Opaque type for the discovery service
 */
typedef struct _DPS_DiscoveryService DPS_DiscoveryService;

/**
 * Allocate resources for a discovery service
 *
 * @param node the node
 * @param serviceId an application-defined topic segment for discovery information
 *
 * @return the service, or NULL if creation failed
 */
DPS_DiscoveryService* DPS_CreateDiscoveryService(DPS_Node* node, const char* serviceId);

/**
 * Store a pointer to application data in a discovery service.
 *
 * @param service the service
 * @param data the data pointer to store
 *
 * @return DPS_OK or an error
 */
DPS_Status DPS_SetDiscoveryServiceData(DPS_DiscoveryService* service, void* data);

/**
 * Get application data pointer previously set by DPS_SetDiscoveryServiceData()
 *
 * @param service the service
 *
 * @return A pointer to the data or NULL if the service is invalid
 */
void* DPS_GetDiscoveryServiceData(DPS_DiscoveryService* service);

/**
 * Function prototype for a discovery handler called when a discovery message is received.
 *
 * @param service the service
 * @param pub opaque handle for the message that was received
 * @param payload payload from the message if any
 * @param len length of the payload
 */
typedef void (*DPS_DiscoveryHandler)(DPS_DiscoveryService* service, const DPS_Publication* pub,
                                     uint8_t* payload, size_t len);

/**
 * Publish this node's discovery information and receive other node's discovery information.
 *
 * @param service the service
 * @param payload optional payload
 * @param len length of the payload
 * @param handler optional callback function to be called when a discovery message is received
 *
 * @return DPS_OK if successful, an error otherwise
 */
DPS_Status DPS_DiscoveryPublish(DPS_DiscoveryService* service, const uint8_t* payload, size_t len,
                                DPS_DiscoveryHandler handler);

/**
 * Function prototype for callback function called when a service is destroyed.
 *
 * @param service the service that was destroyed
 * @param data data passed to DPS_DestroyDiscoveryService()
 *
 */
typedef void (*DPS_OnDiscoveryServiceDestroyed)(DPS_DiscoveryService* service, void* data);

/**
 * Free resources for a discovery service
 *
 * @param service the service
 * @param cb callback function to be called when the service is destroyed
 * @param data data to be passed to the callback function
 *
 * @return
 * - DPS_OK if the service will be destroyed and the callback called
 * - DPS_ERR_NULL service or cb was null
 * - Or an error status code in which case the callback will not be called.
 */
DPS_Status DPS_DestroyDiscoveryService(DPS_DiscoveryService* service,
                                       DPS_OnDiscoveryServiceDestroyed cb, void* data);

#ifdef __cplusplus
}
#endif

#endif
