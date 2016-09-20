
#include <malloc.h>
#include <uv.h>
#include <dps/dps.h>
#include <dps/dps_dbg.h>
#include <dps/dps_event.h>

typedef struct _DPS_Event {
    DPS_Status status;
    void* data;
    uv_cond_t cond;
    uv_mutex_t mutex;
    uint8_t signaled;
} DPS_Event;

void DPS_DestroyEvent(DPS_Event* event)
{
    if (event) {
        uv_mutex_destroy(&event->mutex);
        uv_cond_destroy(&event->cond);
        free(event);
    }
}

DPS_Event* DPS_CreateEvent()
{
    DPS_Event* event = calloc(1, sizeof(DPS_Event));
    if (event) {
        uv_mutex_init(&event->mutex);
        uv_cond_init(&event->cond);
    }
    return event;
}

void DPS_SetEventData(DPS_Event* event, void* data)
{
    if (event) {
        event->data = data;
    }
}

void* DPS_GetEventData(const DPS_Event* event)
{
    return event ? event->data : NULL;
}

void DPS_SignalEvent(DPS_Event* event, DPS_Status status)
{
    if (event) {
        uv_mutex_lock(&event->mutex);
        event->status = status;
        event->signaled = 1;
        uv_cond_signal(&event->cond);
        uv_mutex_unlock(&event->mutex);
    } else {
        DPS_ERRPRINT("DPS_SignalEvent: event == NULL\n");
    }
}

DPS_Status DPS_TimedWaitForEvent(DPS_Event* event, uint16_t timeout)
{
    DPS_Status status;

    if (!timeout) {
        return DPS_WaitForEvent(event);
    }
    if (!event) {
        return DPS_ERR_NULL;
    }
    uv_mutex_lock(&event->mutex);
    while (!event->signaled) {
        if (uv_cond_timedwait(&event->cond, &event->mutex, (uint64_t)timeout * 1000000ull) == UV_ETIMEDOUT) {
            status = DPS_ERR_TIMEOUT;
            break;
        }
    }
    if (event->signaled) {
        event->signaled = 0;
        status = event->status;
    }
    uv_mutex_unlock(&event->mutex);
    return status;
}

DPS_Status DPS_WaitForEvent(DPS_Event* event)
{
    DPS_Status status;

    if (!event) {
        return DPS_ERR_NULL;
    }
    uv_mutex_lock(&event->mutex);
    while (!event->signaled) {
        uv_cond_wait(&event->cond, &event->mutex);
    }
    event->signaled = 0;
    status = event->status;
    uv_mutex_unlock(&event->mutex);
    return status;
}
