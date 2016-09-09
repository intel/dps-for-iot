#ifndef _DPS_EVENT_H
#define _DPS_EVENT_H

#include <uv.h>
#include <dps_err.h>
#include <dps.h>

/**
 * Opaque type for an event
 */
typedef struct _DPS_Event DPS_Event;

/**
 * Create and initialize an event
 */
DPS_Event* DPS_CreateEvent();

/**
 * Destroy an event and free resources
 */
void DPS_DestroyEvent(DPS_Event* event);

/**
 * Set the event data pointer
 */
void DPS_SetEventData(DPS_Event* event, void* data);

/**
 * Get the event data pointer
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

#endif
