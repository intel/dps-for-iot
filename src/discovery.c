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

#include <safe_lib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <memory.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/discovery.h>
#include <dps/private/dps.h>

#include "node.h"
#include "pub.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _SharedBuffer {
    DPS_Buffer buf;
    uint32_t refCount;
    uint8_t data[1];
} SharedBuffer;

static SharedBuffer* CreateSharedBuffer(size_t len)
{
    SharedBuffer* buffer = malloc(sizeof(SharedBuffer) + len - 1);
    if (buffer) {
        buffer->buf.base = buffer->data;
        buffer->buf.len = len;
        buffer->refCount = 1;
    }
    return buffer;
}

static void SharedBufferIncRef(SharedBuffer* buffer)
{
    assert(buffer);
    ++buffer->refCount;
}

static void SharedBufferDecRef(SharedBuffer* buffer)
{
    if (buffer) {
        assert(buffer->refCount > 0);
        if (--buffer->refCount == 0) {
            free(buffer);
        }
    }
}

#define BufferToSharedBuffer(buf)                                       \
    ((SharedBuffer*)(((buf)->base) - offsetof(SharedBuffer, data)))

typedef struct _AckRequest {
    DPS_DiscoveryService* service;
    DPS_Publication* pub;
    uv_timer_t* timer;
} AckRequest;

typedef struct _DPS_DiscoveryService {
    DPS_Node* node;
    DPS_Publication* pub;
    SharedBuffer* payload;
    DPS_Subscription* sub;
    DPS_DiscoveryHandler handler;
    uv_timer_t* timer;
    uint64_t nextTimeout;
    char* topic;
} DPS_DiscoveryService;

static void Destroy(DPS_DiscoveryService* service);
static void OnAck(DPS_Publication* pub, uint8_t* payload, size_t len);
static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

DPS_DiscoveryService* DPS_CreateDiscoveryService(DPS_Node* node, const char* serviceId,
                                                 DPS_DiscoveryHandler handler)
{
    static const int noWildcard = DPS_TRUE;
    DPS_DiscoveryService* service;
    DPS_Status ret;

    DPS_DBGTRACEA("node=%p,serviceId=%s\n", node, serviceId);

    service = calloc(1, sizeof(DPS_DiscoveryService));
    if (!service) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    service->node = node;
    service->topic = malloc(sizeof("$DPS_Discovery/") + strlen(serviceId) + 1);
    if (!service->topic) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    strcpy(service->topic, "$DPS_Discovery/");
    strcat(service->topic, serviceId);
    service->handler = handler;
    service->pub = DPS_CreatePublication(service->node);
    if (!service->pub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetPublicationData(service->pub, service);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_InitPublication(service->pub, (const char**)&service->topic, 1, noWildcard, NULL, OnAck);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_PublicationSetMulticast(service->pub, DPS_TRUE);
    if (ret != DPS_OK) {
        goto Exit;
    }
    service->sub = DPS_CreateSubscription(service->node, (const char**)&service->topic, 1);
    if (!service->sub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetSubscriptionData(service->sub, service);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_SubscriptionSetSerialize(service->sub, DPS_FALSE);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_Subscribe(service->sub, OnPub);
    if (ret != DPS_OK) {
        goto Exit;
    }
Exit:
    if (ret != DPS_OK) {
        Destroy(service);
        service = NULL;
    }
    return service;
}

static DPS_Status CreatePayload(DPS_DiscoveryService* service, DPS_Buffer* bufs, size_t* numBufs)
{
    DPS_Status ret;

    memset(bufs, 0, sizeof(DPS_Buffer) * 2);
    *numBufs = 0;
    ret = DPS_SerializeSubscriptions(service->node, &bufs[(*numBufs)++]);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_SerializeSubscriptions failed - %s\n", DPS_ErrTxt(ret));
        return ret;
    }
    DPS_LockNode(service->node);
    if (service->payload) {
        bufs[(*numBufs)++] = service->payload->buf;
        SharedBufferIncRef(service->payload);
    }
    DPS_UnlockNode(service->node);
    return DPS_OK;
}

static void DestroyPayload(DPS_DiscoveryService* service, const DPS_Buffer* bufs, size_t numBufs)
{
    if (bufs[0].base) {
        free(bufs[0].base);
    }
    if (numBufs > 1) {
        DPS_LockNode(service->node);
        SharedBufferDecRef(BufferToSharedBuffer(&bufs[1]));
        DPS_UnlockNode(service->node);
    }
}

static void PublishCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                      void* data)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(status));
    }
    DestroyPayload(service, bufs, numBufs);
}

static void PublishTimerOnTimeout(uv_timer_t* timer)
{
    DPS_DiscoveryService* service = timer->data;
    DPS_Buffer bufs[2];
    size_t numBufs;
    DPS_Status ret;
    int err;

    ret = CreatePayload(service, bufs, &numBufs);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_PublishBufs(service->pub, bufs, numBufs, 0, PublishCb, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    err = uv_timer_start(service->timer, PublishTimerOnTimeout, service->nextTimeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
    }
    if (service->nextTimeout < 300000) {
        service->nextTimeout = service->nextTimeout * 2;
    }

Exit:
    if (ret != DPS_OK) {
        DestroyPayload(service, bufs, numBufs);
    }
}

static void TimerCloseCb(uv_handle_t* timer)
{
    free(timer);
}

static void LinkCb(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    if (status == DPS_OK) {
        DPS_DBGPRINT("Node is linked to %s\n", DPS_NodeAddrToString(addr));
    } else if (status != DPS_ERR_EXISTS) {
        DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(status));
    }
}

static void OnAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    DPS_Node* node = service->node;
    DPS_RxBuffer rxBuf;
    DPS_Status ret;

    DPS_RxBufferInit(&rxBuf, payload, len);
    if (DPS_MatchPublications(node, &rxBuf)) {
        ret = DPS_Link(node, DPS_NodeAddrToString(DPS_AckGetSenderAddress(pub)), LinkCb, service);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    }
    if (service->handler) {
        service->handler(service, rxBuf.rxPos, DPS_RxBufferAvail(&rxBuf));
    }
}

static void AckCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                  void* data)
{
    DPS_DiscoveryService* service = data;
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(status));
    }
    DestroyPayload(service, bufs, numBufs);
}

static void AckTimerOnTimeout(uv_timer_t* timer)
{
    AckRequest* req = timer->data;
    DPS_DiscoveryService* service = req->service;
    DPS_Publication* pub = req->pub;
    DPS_Buffer bufs[2];
    size_t numBufs = 0;
    DPS_Status ret;

    ret = CreatePayload(service, bufs, &numBufs);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_AckPublicationBufs(pub, bufs, numBufs, AckCb, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }

Exit:
    if (ret != DPS_OK) {
        DestroyPayload(service, bufs, numBufs);
    }
    DPS_DestroyPublication(req->pub, NULL);
    uv_close((uv_handle_t*)req->timer, TimerCloseCb);
    free(req);
}

static void Ack(void* data)
{
    AckRequest* req = data;
    DPS_Node* node = req->service->node;
    uint64_t timeout;
    int err;

    req->timer = malloc(sizeof(uv_timer_t));
    if (!req->timer) {
        err = UV_ENOMEM;
        DPS_ERRPRINT("alloc failed - %s\n", uv_strerror(err));
        goto Exit;
    }
    req->timer->data = req;
    err = uv_timer_init(node->loop, req->timer);
    if (err) {
        DPS_ERRPRINT("uv_timer_init failed - %s\n", uv_strerror(err));
        goto Exit;
    }
    timeout = (DPS_Rand() % 100) + 20;
    err = uv_timer_start(req->timer, AckTimerOnTimeout, timeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        goto Exit;
    }
 Exit:
    if (err) {
        DPS_DestroyPublication(req->pub, NULL);
        if (req->timer) {
            uv_close((uv_handle_t*)req->timer, TimerCloseCb);
        }
        free(req);
    }
}

static DPS_Status ScheduleAck(DPS_DiscoveryService* service, const DPS_Publication* pub)
{
    DPS_Node* node = service->node;
    AckRequest* req = NULL;
    DPS_Status ret;

    req = calloc(1, sizeof(AckRequest));
    if (!req) {
        ret = DPS_ERR_RESOURCES;
        DPS_ERRPRINT("alloc failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    req->service = service;
    req->pub = DPS_CopyPublication(pub);
    if (!req->pub) {
        ret = DPS_ERR_RESOURCES;
        DPS_ERRPRINT("DPS_CopyPublication failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = DPS_NodeScheduleRequest(node, Ack, req);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_NodeScheduleRequest failed - %s\n", DPS_ErrTxt(ret));
    }
 Exit:
    if (ret != DPS_OK) {
        if (req) {
            DPS_DestroyPublication(req->pub, NULL);
            free(req);
        }
    }
    return ret;
}

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetSubscriptionData(sub);
    DPS_Node* node = service->node;
    DPS_RxBuffer rxBuf;
    DPS_Status ret;

    /* Ignore my own publication */
    if (DPS_UUIDCompare(DPS_PublicationGetUUID(service->pub), DPS_PublicationGetUUID(pub)) == 0) {
        return;
    }
    DPS_RxBufferInit(&rxBuf, payload, len);
    if (DPS_MatchPublications(node, &rxBuf)) {
        ret = DPS_Link(node, DPS_NodeAddrToString(DPS_PublicationGetSenderAddress(pub)), LinkCb, service);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    } else if (DPS_PublicationIsAckRequested(pub)) {
        ScheduleAck(service, pub);
    }
    if (service->handler) {
        service->handler(service, rxBuf.rxPos, DPS_RxBufferAvail(&rxBuf));
    }
}

static void StartTimer(void* data)
{
    DPS_DiscoveryService* service = data;
    DPS_Node* node = service->node;
    int err;

    if (!service->timer) {
        service->timer = malloc(sizeof(uv_timer_t));
        if (!service->timer) {
            DPS_ERRPRINT("alloc failed - %s\n", DPS_ErrTxt(DPS_ERR_RESOURCES));
            return;
        }
        service->timer->data = service;
        err = uv_timer_init(node->loop, service->timer);
        if (err) {
            DPS_ERRPRINT("uv_timer_init failed - %s\n", uv_strerror(err));
            return;
        }
    } else {
        uv_timer_stop(service->timer);
    }
    service->nextTimeout = (DPS_Rand() % 100) + 20;
    err = uv_timer_start(service->timer, PublishTimerOnTimeout, service->nextTimeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        return;
    }
    service->nextTimeout += 1000;
}

DPS_Status DPS_DiscoveryPublish(DPS_DiscoveryService* service, const uint8_t* payload, size_t len)
{
    SharedBuffer* buffer = NULL;
    DPS_Status ret;

    DPS_DBGTRACEA("service=%p\n", service);

    if (!service) {
        return DPS_ERR_NULL;
    }
    if (len && !payload) {
        return DPS_ERR_ARGS;
    }

    if (len) {
        buffer = CreateSharedBuffer(len);
        if (!buffer) {
            return DPS_ERR_RESOURCES;
        }
        memcpy_s(buffer->buf.base, buffer->buf.len, payload, len);
    }
    DPS_LockNode(service->node);
    SharedBufferDecRef(service->payload);
    service->payload = buffer;
    DPS_UnlockNode(service->node);
    ret = DPS_NodeScheduleRequest(service->node, StartTimer, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start discovery: %s\n", DPS_ErrTxt(ret));
    }
    return ret;
}

static void OnPubDestroyed(DPS_Publication* pub)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    service->pub = NULL;
    Destroy(service);
}

static void OnSubDestroyed(DPS_Subscription* sub)
{
    DPS_DiscoveryService* service = DPS_GetSubscriptionData(sub);
    service->sub = NULL;
    Destroy(service);
}

static void ServiceTimerCloseCb(uv_handle_t* timer)
{
    DPS_DiscoveryService* service = timer->data;
    free(service->timer);
    service->timer = NULL;
    Destroy(service);
}

static void Destroy(DPS_DiscoveryService* service)
{
    if (!service) {
        return;
    }
    if (service->timer) {
        uv_close((uv_handle_t*)service->timer, ServiceTimerCloseCb);
    } else if (service->sub) {
        DPS_DestroySubscription(service->sub, OnSubDestroyed);
    } else if (service->pub) {
        DPS_DestroyPublication(service->pub, OnPubDestroyed);
    } else {
        SharedBufferDecRef(service->payload);
        if (service->topic) {
            free(service->topic);
        }
        free(service);
    }
}

static void DestroyService(void* data)
{
    DPS_DiscoveryService* service = data;
    Destroy(service);
}

void DPS_DestroyDiscoveryService(DPS_DiscoveryService* service)
{
    DPS_DBGTRACEA("service=%p\n", service);

    if (service) {
        DPS_NodeScheduleRequest(service->node, DestroyService, service);
    }
}
