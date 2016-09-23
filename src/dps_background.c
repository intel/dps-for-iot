#include <stdlib.h>
#include <dps/dps_dbg.h>
#include "dps_node.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _BackgroundHandler {
    DPS_Node* node;
    void (*asyncRun)(DPS_Node*);
    uv_async_t async;
    void (*timerRun)(DPS_Node*);
    uv_timer_t timer;
} BackgroundHandler;

static void BackgroundRun(uv_async_t* async)
{
    BackgroundHandler* bg = (BackgroundHandler*)async->data;
    bg->asyncRun(bg->node);
}

static void TimerRun(uv_timer_t* timer)
{
    BackgroundHandler* bg = (BackgroundHandler*)timer->data;
    bg->timerRun(bg->node);
}

BackgroundHandler* DPS_BackgroundCreate(DPS_Node* node, void (*run)(DPS_Node*))
{
    BackgroundHandler* bg = malloc(sizeof(BackgroundHandler));
    if (!bg) {
        return NULL;
    }
    bg->node = node;
    bg->asyncRun = run;
    bg->async.data = bg;
    int r = uv_async_init(node->loop, &bg->async, BackgroundRun);
    if (r) {
        free(bg);
    }
    bg->timer.data = bg;
    r = uv_timer_init(node->loop, &bg->timer);
    if (r) {
        free(bg);
    }
    return bg;
}

void DPS_BackgroundScheduleNow(BackgroundHandler* bg)
{
    uv_async_send(&bg->async);
}

void DPS_BackgroundSchedule(BackgroundHandler* bg, void (*run)(DPS_Node*), uint64_t delayMsecs)
{
    bg->timerRun = run;
    uv_timer_start(&bg->timer, TimerRun, delayMsecs, 0);
}

static void TimerClose(uv_handle_t* handle)
{
    BackgroundHandler* bg = (BackgroundHandler*)handle->data;
    free(bg);
}

static void AsyncClose(uv_handle_t* handle)
{
    BackgroundHandler* bg = (BackgroundHandler*)handle->data;
    uv_close((uv_handle_t*)&bg->timer, TimerClose);
}

void DPS_BackgroundClose(BackgroundHandler* bg)
{
    assert(!uv_is_closing((uv_handle_t*)&bg->async));
    assert(!uv_is_closing((uv_handle_t*)&bg->timer));
    uv_close((uv_handle_t*)&bg->async, AsyncClose);
}
