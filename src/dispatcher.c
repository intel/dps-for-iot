
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

#include <stdlib.h>
#include <safe_lib.h>
#include <uv.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/dispatcher.h>
#include "node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

struct _DPS_Dispatcher {
    DPS_Node* node;
    uv_async_t async;
    uv_timer_t timer;
    DPS_DispatchFunc func;
    DPS_DelayedFunc delayedFunc;
    void* arg;
    int delay;
    int busy;
};

static void AsyncClosed(uv_handle_t* handle)
{
    free(handle->data);
}

static void TimerClosed(uv_handle_t* handle)
{
    DPS_Dispatcher* dispatcher = (DPS_Dispatcher*)handle->data;
    uv_close((uv_handle_t*)&dispatcher->async, AsyncClosed);
}

static void DispatchTimeout(uv_timer_t* handle)
{
    DPS_DispatchFunc func;
    DPS_Dispatcher* dispatcher = (DPS_Dispatcher*)handle->data;
    DPS_Node* node;
    void* arg;

    DPS_LockNode(dispatcher->node);
    dispatcher->busy = DPS_FALSE;
    func = dispatcher->func;
    arg = dispatcher->arg;
    node = dispatcher->node;
    DPS_UnlockNode(dispatcher->node);
    func(node, dispatcher, arg);
}

static void DispatchTask(uv_async_t* handle)
{
    int r;
    DPS_Dispatcher* dispatcher = (DPS_Dispatcher*)handle->data;

    DPS_LockNode(dispatcher->node);
    r = uv_timer_start(&dispatcher->timer, DispatchTimeout, dispatcher->delay, 0);
    if (!r) {
        dispatcher->busy = DPS_FALSE;
    }
    DPS_UnlockNode(dispatcher->node);
}

DPS_Dispatcher* DPS_CreateDispatcher(DPS_Node* node, DPS_DispatchFunc func)
{
    int r;
    DPS_Dispatcher* dispatcher;

    DPS_DBGTRACE();

    if (!node || !func) {
        return NULL;
    }
    dispatcher = calloc(sizeof(DPS_Dispatcher), 1);
    if (!dispatcher) {
        return NULL;
    }
    dispatcher->node = node;
    dispatcher->timer.data = dispatcher;
    r = uv_timer_init(node->loop, &dispatcher->timer);
    if (r) {
        DPS_ERRPRINT("uv_timer_init() - %s\n", uv_err_name(r));
        free(dispatcher);
        return NULL;
    }
    dispatcher->async.data = dispatcher;
    r = uv_async_init(node->loop, &dispatcher->async, DispatchTask);
    if (r) {
        DPS_ERRPRINT("uv_async_init() - %s\n", uv_err_name(r));
        uv_close((uv_handle_t*)&dispatcher->timer, NULL);
        free(dispatcher);
        return NULL;
    }
    dispatcher->func = func;
    return dispatcher;
}

DPS_Status DPS_Dispatch(DPS_Dispatcher* dispatcher, void* data, int delay)
{
    if (!dispatcher) {
        return DPS_ERR_NULL;
    }
    DPS_LockNode(dispatcher->node);
    if (dispatcher->busy) {
        DPS_UnlockNode(dispatcher->node);
        return DPS_ERR_BUSY;
    }
    dispatcher->busy = DPS_TRUE;
    dispatcher->arg = data;
    dispatcher->delay = delay;
    uv_async_send(&dispatcher->async);
    DPS_UnlockNode(dispatcher->node);
    return DPS_OK;
}

void DPS_DestroyDispatcher(DPS_Dispatcher* dispatcher)
{
    DPS_DBGTRACE();
    if (dispatcher) {
        DPS_LockNode(dispatcher->node);
        while (dispatcher->busy) {
            DPS_UnlockNode(dispatcher->node);
            DPS_LockNode(dispatcher->node);
        }
        uv_close((uv_handle_t*)&dispatcher->timer, TimerClosed);
        DPS_UnlockNode(dispatcher->node);
    }
}

static void CallFunc(DPS_Node* node, DPS_Dispatcher* dispatcher, void* data)
{
    dispatcher->delayedFunc(node, data);
    DPS_DestroyDispatcher(dispatcher);
}

DPS_Status DPS_ScheduleCall(DPS_Node* node, DPS_DelayedFunc func, void* data, int delay)
{
    DPS_Status ret;
    DPS_Dispatcher* dispatcher = DPS_CreateDispatcher(node, CallFunc);
    if (dispatcher) {
        dispatcher->delayedFunc = func;
        ret = DPS_Dispatch(dispatcher, data, delay);
    } else {
        ret = DPS_ERR_RESOURCES;
    }
    return ret;
}
