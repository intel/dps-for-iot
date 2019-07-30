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

#include <stdint.h>
#include <dps/err.h>
#include <dps/dps.h>

/**
  * Opaque type for the discovery service
  */
typedef struct _DPS_DiscoveryService DPS_DiscoveryService;

/**
  * Allocate resources for a discovery service
  */
DPS_DiscoveryService* DPS_CreateDiscoveryService(DPS_Node* node, const char* serviceId);

/**
  * Start a discovery service
  */
DPS_Status DPS_DiscoveryStart(DPS_DiscoveryService* service);

/**
  * Stop a discovery service
  */
void DPS_DiscoveryStop(DPS_DiscoveryService* service);

/**
  * Free resources for a discovery service
  */
void DPS_DestroyDiscoveryService(DPS_DiscoveryService* service);


#endif
