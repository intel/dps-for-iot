/**
 * @file
 * Wrapper for platform dependent timer function
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

#ifndef _TIMER_H
#define _TIMER_H

#include <stdint.h>
#include <dps/err.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DPS_Timer DPS_Timer;

typedef void (*DPS_TimeoutCallback)(DPS_Timer* timer, void* data);

/**
 * Allocate a timer and start it running
 *
 * @param timeout  Timeout specified in milliseconds
 * @param cb       Callback function called when the timeout expires
 * @param data     Data passed to the callback function
 */
DPS_Timer* DPS_TimerSet(uint16_t timeout, DPS_TimeoutCallback cb, void* data);

/**
  * Restart an existing timer
  *
  * @param timer    The timer to restart
  * @param timeout  Timeout specified in milliseconds
  */
DPS_Status DPS_TimerReset(DPS_Timer* timer, uint16_t timeout);

/**
  * Cancel an existing timer and free any resources
  *
  * @param timer    The timer to cancel
  */
DPS_Status DPS_TimerCancel(DPS_Timer* timer);

#ifdef __cplusplus
}
#endif

#endif
