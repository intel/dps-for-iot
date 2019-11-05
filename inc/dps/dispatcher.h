/**
 * @file
 * Register functions to be called after a timeout period expires
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

#ifndef _DPS_DISPATCHER_H
#define _DPS_DISPATCHER_H

#include <dps/err.h>
#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup event Dispatcher
 * Register functions to be called after a timeout period expires
 * @{
 */

/**
 * Opaque type for an dispatcher
 */
typedef struct _DPS_Dispatcher DPS_Dispatcher;

/**
  * Prototype for function to be called by a dispatcher. This function will be called on
  * the main (internal) node thread and must not block.
  *
  * @param node        The node used for this dispatcher
  * @param dispatcher  The dispatcher for this call
  * @param data        The data passed to the DPS_Dispatch() call
  */
typedef void (*DPS_DispatchFunc)(DPS_Node* node, DPS_Dispatcher* dispatcher, void* data);

/**
 * Create a dispatcher and register the function to be called.
 *
 * @param node   The node to be used for this dispatcher
 * @param func   The function to be called
 * @return The created dispatcher, or NULL if creation failed
 */
DPS_Dispatcher* DPS_CreateDispatcher(DPS_Node* node, DPS_DispatchFunc func);

/**
 * Call the function registered when the dispatcher was created.
 *
 * @param dispatcher  The dispatcher to call
 * @param data        Data to be passed to the function
 * @param delay       Time delay in millseconds before the function will be called
 */
DPS_Status DPS_Dispatch(DPS_Dispatcher* dispatcher, void* data, int delay);

/**
 * Destroy a dispatcher and free resources
 *
 * @param dispatcher   The dispatcher to destroy
 */
void DPS_DestroyDispatcher(DPS_Dispatcher* dispatcher);

/**
  * Prototype for a delayed dispatched function call. This function will be called on
  * the main (internal) node thread and must not block. The dispatcher is internal
  * and not exposed in this usage.
  *
  * @param node        The node used for this dispatcher
  * @param data        The data passed to the DPS_CallDelayedFunc() call
  */
typedef void (*DPS_DelayedFunc)(DPS_Node* node, void* data);

/**
  * Wrapper function that creates a dispatcher and schedules a function to be called
  * after a delay. The dispatcher is destroyed after the function has been called.
  *
  * @param node   The node to be used for the internal dispatcher
  * @param func   The function to be called
  * @param data   Data to be passed to the function
  * @param delay  Time delay in millseconds before the function will be called
  */
DPS_Status DPS_ScheduleCall(DPS_Node* node, DPS_DelayedFunc func, void* data, int delay);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
