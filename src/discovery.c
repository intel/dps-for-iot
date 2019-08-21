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

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

typedef struct _AckRequest {
    DPS_DiscoveryService* service;
    DPS_Publication* pub;
    uv_timer_t* timer;
} AckRequest;

typedef struct _DPS_DiscoveryService {
    DPS_Node* node;
    DPS_Publication* pub;
    DPS_Subscription* sub;
    uv_timer_t* timer;
    uint64_t nextTimeout;
    char* topic;
} DPS_DiscoveryService;

DPS_DiscoveryService* DPS_CreateDiscoveryService(DPS_Node* node, const char* serviceId)
{
    DPS_DiscoveryService* svc = calloc(1, sizeof(DPS_DiscoveryService));
    if (svc) {
        svc->node = node;
        svc->topic = malloc(sizeof("$DPS_Discovery/") + strlen(serviceId) + 1);
        if (svc->topic) {
            strcpy(svc->topic, "$DPS_Discovery/");
            strcat(svc->topic, serviceId);
        } else {
            free(svc);
            svc = NULL;
        }
    }
    return svc;
}

static void DiscoveryPublishCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status, void* data)
{
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(status));
    }
    free(bufs[0].base);
}

static void DiscoveryTimerOnTimeout(uv_timer_t* timer)
{
    DPS_DiscoveryService* service = timer->data;
    DPS_Node* node = service->node;
    DPS_Buffer subs;
    DPS_Status ret;
    int err;

    memset(&subs, 0, sizeof(DPS_Buffer));
    ret = DPS_SerializeSubscriptions(node, &subs);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_SerializeSubscriptions failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = DPS_PublishBufs(service->pub, &subs, 1, 0, DiscoveryPublishCb, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    err = uv_timer_start(service->timer, DiscoveryTimerOnTimeout, service->nextTimeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        ret = DPS_ERR_FAILURE;
        goto Exit;
    }
    if (service->nextTimeout < 300000) {
        service->nextTimeout = service->nextTimeout * 2;
    }

Exit:
    if (ret != DPS_OK) {
        if (subs.base) {
            free(subs.base);
        }
    }
}

static void TimerCloseCb(uv_handle_t* timer)
{
    free(timer);
}

static void DiscoveryLinkCb(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    if (status == DPS_OK) {
        DPS_PRINT("Node is linked to %s\n", DPS_NodeAddrToString(addr));
    } else if (status != DPS_ERR_EXISTS) {
        DPS_ERRPRINT("Node is not linked to %s\n", DPS_NodeAddrToString(addr), DPS_ErrTxt(status));
    }
}

static void DiscoveryOnAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    DPS_Node* node = service->node;
    DPS_Buffer remoteSubs;
    DPS_Status ret;

    remoteSubs.base = payload;
    remoteSubs.len = len;
    if (DPS_MatchPublications(node, &remoteSubs)) {
        ret = DPS_LinkRemoteAddr(node, DPS_AckGetSenderAddress(pub), DiscoveryLinkCb, service);
        if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void AckCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status, void* data)
{
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(status));
    }
    free(bufs[0].base);
}

static void AckTimerOnTimeout(uv_timer_t* timer)
{
    AckRequest* req = timer->data;
    DPS_DiscoveryService* service = req->service;
    DPS_Node* node = service->node;
    DPS_Publication* pub = req->pub;
    DPS_Buffer subs;
    DPS_Status ret;

    memset(&subs, 0, sizeof(DPS_Buffer));
    ret = DPS_SerializeSubscriptions(node, &subs);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_SerializeSubscriptions failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = DPS_AckPublicationBufs(pub, &subs, 1, AckCb, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }

Exit:
    if (ret != DPS_OK) {
        if (subs.base) {
            free(subs.base);
        }
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

static DPS_Status DiscoveryScheduleAck(DPS_DiscoveryService* service, const DPS_Publication* pub)
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

static void DiscoveryOnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetSubscriptionData(sub);
    DPS_Node* node = service->node;
    DPS_Buffer remoteSubs;
    DPS_Status ret;

    /* Ignore my own publication */
    if (DPS_UUIDCompare(DPS_PublicationGetUUID(service->pub), DPS_PublicationGetUUID(pub)) == 0) {
        return;
    }
    remoteSubs.base = payload;
    remoteSubs.len = len;
    if (DPS_MatchPublications(node, &remoteSubs)) {
        ret = DPS_LinkRemoteAddr(node, DPS_PublicationGetSenderAddress(pub), DiscoveryLinkCb, service);
        if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    } else if (DPS_PublicationIsAckRequested(pub)) {
        DiscoveryScheduleAck(service, pub);
    }
}

static void DiscoveryStartTimer(void* data)
{
    DPS_DiscoveryService* service = data;
    DPS_Node* node = service->node;
    int err;

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
    service->nextTimeout = (DPS_Rand() % 100) + 20;
    err = uv_timer_start(service->timer, DiscoveryTimerOnTimeout, service->nextTimeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        return;
    }
    service->nextTimeout += 1000;
}

static void DiscoveryStopTimer(void* data)
{
    uv_handle_t* timer = data;
    uv_close(timer, TimerCloseCb);
}

DPS_Status DPS_DiscoveryStart(DPS_DiscoveryService* service)
{
    DPS_Status ret;
    static const int noWildcard = DPS_TRUE;

    if (!service) {
        return DPS_ERR_NULL;
    }
    service->pub = DPS_CreatePublication(service->node);
    if (!service->pub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetPublicationData(service->pub, service);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_InitPublication(service->pub, (const char**)&service->topic, 1, noWildcard, NULL, DiscoveryOnAck);
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
    ret = DPS_Subscribe(service->sub, DiscoveryOnPub);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_NodeScheduleRequest(service->node, DiscoveryStartTimer, service);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start discovery: %s\n", DPS_ErrTxt(ret));
        DPS_DiscoveryStop(service);
    }
    return ret;
}

void DPS_DiscoveryStop(DPS_DiscoveryService* service)
{
    if (service) {
        if (service->timer) {
            DPS_NodeScheduleRequest(service->node, DiscoveryStopTimer, service->timer);
            service->timer = NULL;
        }
        DPS_DestroySubscription(service->sub, NULL);
        DPS_DestroyPublication(service->pub, NULL);
    }
}

void DPS_DestroyDiscoveryService(DPS_DiscoveryService* service)
{
    if (service) {
        DPS_DiscoveryStop(service);
        if (service->topic) {
            free(service->topic);
        }
        free(service);
    }
}

