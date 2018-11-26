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

#include <stdint.h>
#include <stddef.h>
#include <dps/err.h>
#include <dps/key_mgmt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_TRUE  1 /**< TRUE boolean value */
#define DPS_FALSE 0 /**< FALSE boolean value */

/**
 * Opaque type for a DPS node
 */
typedef struct _DPS_Node DPS_Node;

DPS_Node* DPS_Init();

void DPS_Terminate(DPS_Node* node);


#ifdef __cplusplus
}
#endif

#endif
