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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include <dps/dps.h>
#include <dps/err.h>
#include <dps/dbg.h>
#include <dps/private/timer.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);


struct _DPS_Timer {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cv;
    uint16_t timeout;
    DPS_TimeoutCallback cb;
    void* data;
};

static void* TimerThread(void* arg)
{
    DPS_Timer* timer = (DPS_Timer*)arg;
    while (1) {
        int ret;
        pthread_mutex_lock(&timer->mutex);
        if (timer->timeout) {
            struct timespec now;
            struct timespec later;

            clock_gettime(CLOCK_REALTIME, &now);
            later.tv_nsec = now.tv_nsec + timer->timeout * 1000000UL;
            later.tv_sec = now.tv_sec + later.tv_nsec / 1000000000UL;
            later.tv_nsec %= 1000000000UL;
            ret = pthread_cond_timedwait(&timer->cv, &timer->mutex, &later);
            if (ret == ETIMEDOUT) {
                timer->timeout = 0;
                timer->cb(timer, timer->data);
            }
        } else {
            ret = pthread_cond_wait(&timer->cv, &timer->mutex);
        }
        pthread_mutex_unlock(&timer->mutex);
    }
    return NULL;
}

DPS_Timer* DPS_TimerSet(uint16_t timeout, DPS_TimeoutCallback cb, void* data)
{
    static DPS_Timer* timer;

    if (!timer) {
        int ret;
        timer = calloc(1, sizeof(DPS_Timer));
        ret = pthread_mutex_init(&timer->mutex, NULL);
        if (ret) {
            DPS_DBGPRINT("Failed to create mutex\n");
            return NULL;
        }
        ret = pthread_cond_init(&timer->cv, NULL);
        if (ret) {
            DPS_DBGPRINT("Failed to create condition variable\n");
            return NULL;
        }
        ret = pthread_create(&timer->thread, NULL, TimerThread, timer);
        if (ret) {
            DPS_DBGPRINT("Failed to create timer thread\n");
            return NULL;
        }
    }
    DPS_TimerReset(timer, timeout);
    return timer;
}

DPS_Status DPS_TimerReset(DPS_Timer* timer, uint16_t timeout)
{
    if (!timer) {
        return DPS_ERR_NULL;
    }
    pthread_mutex_lock(&timer->mutex);
    timer->timeout = timeout;
    pthread_cond_signal(&timer->cv);
    pthread_mutex_unlock(&timer->mutex);
    return DPS_OK;
}

DPS_Status DPS_TimerCancel(DPS_Timer* timer)
{
    return DPS_TimerReset(timer, 0);
}
