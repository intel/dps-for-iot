/**
 * @file
 * Signal and wait on application-created events
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

#ifndef _DPS_EVENT_H
#define _DPS_EVENT_H

#include <dps/err.h>
#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup event Event
 * Signal and wait on application-created events.
 * @{
 */

/**
 * Opaque type for an event
 */
typedef struct _DPS_Event DPS_Event;

/**
 * Create and initialize an event
 *
 * @return The created event, or NULL if creation failed
 */
DPS_Event* DPS_CreateEvent();

/**
 * Destroy an event and free resources
 *
 * @param event   The event to destroy
 */
void DPS_DestroyEvent(DPS_Event* event);

/**
 * Set the event application data
 *
 * @param event   The event to set an application data on
 * @param data    The data to set
 */
void DPS_SetEventData(DPS_Event* event, void* data);

/**
 * Get the event application data
 *
 * @param event   The event to get the application data from
 *
 * @return The application data
 */
void* DPS_GetEventData(const DPS_Event* event);

/**
 * Signal an event
 *
 * @param event    Event to signal
 * @param status   A status code to pass to the event waiter
 */
void DPS_SignalEvent(DPS_Event* event, DPS_Status status);

/**
 * Wait for an event to be signalled
 *
 * @param event    Event to wait for
 *
 * @return  The status passed to DPS_SignalEvent()
 */
DPS_Status DPS_WaitForEvent(DPS_Event* event);

/**
 * Wait for an event to be signalled with a timeout
 *
 * @param event    Event to wait for
 * @param timeout  Timeout in milliseconds
 *
 * @return  The status passed to DPS_SignalEvent() or DPS_ERR_TIMEOUT if the call timed out.
 */
DPS_Status DPS_TimedWaitForEvent(DPS_Event* event, uint16_t timeout);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
