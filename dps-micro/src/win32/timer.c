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

#include <windows.h>
#include <dps/private/timer.h>

struct _DPS_Timer {
    HANDLE handle;
    DPS_TimeoutCallback cb;
    void* data;
};

static void CALLBACK TimerCB(_In_ PVOID lpParam, _In_ BOOLEAN timedOut)
{
    DPS_Timer* timer = (DPS_Timer*)lpParam;

    if (timedOut) {
        timer->cb(timer, timer->data);
    }
}

DPS_Timer* DPS_TimerSet(uint16_t timeout, DPS_TimeoutCallback cb, void* data)
{
    DPS_Timer* timer = malloc(sizeof(DPS_Timer));

    timer->cb = cb;
    timer->data = data;
    if (CreateTimerQueueTimer(&timer->handle, NULL, TimerCB, timer, timeout, 0, 0)) {
        return timer;
    } else {
        free(timer);
        return NULL;
    }
}

DPS_Status DPS_TimerReset(DPS_Timer* timer, uint16_t timeout)
{
    if (!timer) {
        return DPS_ERR_NULL;
    }
    DeleteTimerQueueTimer(NULL, timer->handle, NULL);
    CreateTimerQueueTimer(&timer->handle, NULL, TimerCB, timer, timeout, 0, 0);
    return DPS_OK;
}

DPS_Status DPS_TimerCancel(DPS_Timer* timer)
{
    if (!timer) {
        return DPS_ERR_NULL;
    }
    DeleteTimerQueueTimer(NULL, timer->handle, NULL);
    free(timer);
    return DPS_OK;
}
