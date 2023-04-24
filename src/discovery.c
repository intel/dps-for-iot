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
#include <dps/private/cbor.h>
#include <dps/private/dps.h>

#include "node.h"
#include "pub.h"
#include "sub.h"
#include "topics.h"

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
    DPS_Queue queue;
    DPS_DiscoveryService* service;
    DPS_Publication* pub;
    uv_timer_t* timer;
    NodeRequest delayReq;
} AckRequest;

typedef struct _HandlerData {
    DPS_Queue queue;
    DPS_DiscoveryService* service;
    DPS_Publication* pub;
    uint8_t* data;
    size_t dataLen;
} HandlerData;

typedef struct _DPS_DiscoveryService {
    void* userData;
    DPS_Node* node;
    DPS_Publication* pub;
    SharedBuffer* payload;
    DPS_Subscription* sub;
    DPS_DiscoveryHandler handler;
    int subscribed;
    uv_timer_t* timer;
    uint64_t nextTimeout;
    DPS_Queue ackQueue;
    char* topic;
    DPS_OnDiscoveryServiceDestroyed destroyCb;
    void* destroyData;
    DPS_Queue handlerQueue;
} DPS_DiscoveryService;

static void Destroy(DPS_DiscoveryService* service);
static void OnAck(DPS_Publication* pub, uint8_t* payload, size_t len);
static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len);

static DPS_Status EncodeDiscoveryPayload(DPS_DiscoveryService* service, uint8_t msgType, DPS_Buffer bufs[2])
{
    DPS_Status ret;
    DPS_TxBuffer txBuf;
    DPS_BitVector* interests = NULL;
    DPS_Subscription* sub;
    size_t len;
    size_t n;

    DPS_DBGTRACE();

    DPS_LockNode(service->node);
    DPS_TxBufferClear(&txBuf);
    interests = DPS_BitVectorAlloc();
    if (!interests) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    for (sub = service->node->subscriptions; sub; sub = sub->next) {
        if (sub->flags & SUB_FLAG_SERIALIZE) {
            ret = DPS_BitVectorUnion(interests, sub->bf);
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
    }
    n = 1;
    len = 0;
    if (msgType == DPS_MSG_TYPE_ACK) {
        ++n;
        len += CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF_BYTES(sizeof(DPS_UUID));
    }
    len += CBOR_SIZEOF(uint8_t) + DPS_BitVectorSerializeMaxSize(interests);
    if (service->payload) {
        ++n;
        len += CBOR_SIZEOF(uint8_t);
    }
    len += CBOR_SIZEOF_MAP(n);
    ret = DPS_TxBufferInit(&txBuf, NULL, len);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = CBOR_EncodeMap(&txBuf, n);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (msgType == DPS_MSG_TYPE_ACK) {
        ret = CBOR_EncodeUint8(&txBuf, DPS_CBOR_KEY_PUB_ID);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = CBOR_EncodeUUID(&txBuf, DPS_PublicationGetUUID(service->pub));
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    ret = CBOR_EncodeUint8(&txBuf, DPS_CBOR_KEY_INTERESTS);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_BitVectorSerialize(interests, &txBuf);
    if (ret != DPS_OK) {
        goto Exit;
    }
    if (service->payload) {
        ret = CBOR_EncodeUint8(&txBuf, DPS_CBOR_KEY_DATA);
        if (ret != DPS_OK) {
            goto Exit;
        }
        ret = CBOR_EncodeLength(&txBuf, service->payload->buf.len, CBOR_BYTES);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
Exit:
    DPS_BitVectorFree(interests);
    if (ret == DPS_OK) {
        bufs[0].base = txBuf.base;
        bufs[0].len = DPS_TxBufferUsed(&txBuf);
        if (service->payload) {
            bufs[1] = service->payload->buf;
            SharedBufferIncRef(service->payload);
        }
    } else {
        DPS_TxBufferFree(&txBuf);
    }
    DPS_UnlockNode(service->node);
    return ret;
}

static DPS_Status DecodeDiscoveryPayload(DPS_DiscoveryService* service, uint8_t msgType, DPS_UUID* pubId, int* match,
                                         uint8_t** data, size_t* dataLen, uint8_t* payload, size_t len)
{
    static const int32_t Keys[] = { DPS_CBOR_KEY_PUB_ID, DPS_CBOR_KEY_INTERESTS, DPS_CBOR_KEY_DATA };
    DPS_Node* node = service->node;
    DPS_RxBuffer rxBuf;
    uint16_t keysMask;
    DPS_BitVector* interests = NULL;
    CBOR_MapState mapState;
    DPS_Publication* pub;
    DPS_Status ret;

    DPS_DBGTRACE();

    DPS_RxBufferInit(&rxBuf, payload, len);
    ret = DPS_ParseMapInit(&mapState, &rxBuf, NULL, 0, Keys, A_SIZEOF(Keys));
    if (ret != DPS_OK) {
        goto Exit;
    }
    keysMask = 0;
    while (!DPS_ParseMapDone(&mapState)) {
        int32_t key = 0;
        ret = DPS_ParseMapNext(&mapState, &key);
        if (ret != DPS_OK) {
            break;
        }
        switch (key) {
        case DPS_CBOR_KEY_PUB_ID:
            keysMask |= (1 << key);
            if (!pubId) {
                ret = DPS_ERR_INVALID;
                break;
            }
            ret = CBOR_DecodeUUID(&rxBuf, pubId);
            break;
        case DPS_CBOR_KEY_INTERESTS:
            keysMask |= (1 << key);
            if (interests) {
                ret = DPS_ERR_INVALID;
                break;
            }
            interests = DPS_BitVectorAlloc();
            if (!interests) {
                ret = DPS_ERR_RESOURCES;
                break;
            }
            ret = DPS_BitVectorDeserialize(interests, &rxBuf);
            break;
        case DPS_CBOR_KEY_DATA:
            keysMask |= (1 << key);
            ret = CBOR_DecodeBytes(&rxBuf, data, dataLen);
            break;
        default:
            break;
        }
        if (ret != DPS_OK) {
            break;
        }
    }
    if (ret != DPS_OK) {
        goto Exit;
    }
    if ((msgType == DPS_MSG_TYPE_ACK) && ((keysMask & (1 << DPS_CBOR_KEY_PUB_ID)) == 0)) {
        ret = DPS_ERR_INVALID;
        goto Exit;
    }

    DPS_BitVectorDump(interests, DPS_TRUE);

    *match = DPS_FALSE;
    DPS_LockNode(node);
    for (pub = node->publications; pub && !(*match); pub = pub->next) {
        *match = DPS_BitVectorIncludes(interests, pub->bf);
    }
    DPS_UnlockNode(node);

Exit:
    DPS_BitVectorFree(interests);
    return ret;
}

DPS_DiscoveryService* DPS_CreateDiscoveryService(DPS_Node* node, const char* serviceId)
{
    DPS_DiscoveryService* service;
    DPS_Status ret;

    if (!node) {
        return NULL;
    }
    /* Use default service id if one is not supplied */
    if (!serviceId) {
        serviceId = "generic_discovery";
    }
    DPS_DBGTRACEA("node=%p,serviceId=%s\n", node, serviceId);

    service = calloc(1, sizeof(DPS_DiscoveryService));
    if (!service) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    service->node = node;
    DPS_QueueInit(&service->ackQueue);
    DPS_QueueInit(&service->handlerQueue);
    service->topic = malloc(sizeof("$DPS_Discovery/") + strlen(serviceId) + 1);
    if (!service->topic) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    strcpy(service->topic, "$DPS_Discovery/");
    strcat(service->topic, serviceId);
    service->pub = DPS_CreatePublication(service->node);
    if (!service->pub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetPublicationData(service->pub, service);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_InitPublication(service->pub, (const char**)&service->topic, 1, DPS_FALSE, OnAck);
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
Exit:
    if (ret != DPS_OK) {
        Destroy(service);
        service = NULL;
    }
    return service;
}

DPS_Status DPS_SetDiscoveryServiceData(DPS_DiscoveryService* service, void* data)
{
    if (service) {
        service->userData = data;
        return DPS_OK;
    } else {
        return DPS_ERR_NULL;
    }
}

void* DPS_GetDiscoveryServiceData(DPS_DiscoveryService* service)
{
    return service ? service->userData : NULL;
}

static void DestroyPayload(DPS_Node* node, const DPS_Buffer* bufs, size_t numBufs)
{
    if (bufs[0].base) {
        free(bufs[0].base);
    }
    if ((numBufs > 1) && bufs[1].base) {
        DPS_LockNode(node);
        SharedBufferDecRef(BufferToSharedBuffer(&bufs[1]));
        DPS_UnlockNode(node);
    }
}

static void PublishCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                      void* data)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(status));
    }
    DestroyPayload(service->node, bufs, numBufs);
}

static void PublishTimerOnTimeout(uv_timer_t* timer)
{
    DPS_DiscoveryService* service = timer->data;
    DPS_Buffer bufs[2];
    DPS_Status ret;
    int err;

    memset(bufs, 0, sizeof(bufs));
    ret = EncodeDiscoveryPayload(service, DPS_MSG_TYPE_PUB, bufs);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_PublishBufs(service->pub, bufs, 2, 0, PublishCb, service);
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
        DestroyPayload(service->node, bufs, 2);
    }
}

static void TimerCloseCb(uv_handle_t* timer)
{
    free(timer);
}

static DPS_Publication* CopyPublication(const DPS_Publication* pub, const DPS_UUID* ackUuid)
{
    DPS_Publication* copy;
    DPS_Status ret = DPS_ERR_RESOURCES;

    DPS_DBGTRACE();

    copy = calloc(1, sizeof(DPS_Publication));
    if (!copy) {
        DPS_ERRPRINT("alloc failure: no memory\n");
        goto Exit;
    }
    copy->flags = PUB_FLAG_IS_COPY;
    copy->sequenceNum = pub->ack.sequenceNum;
    copy->ttl = pub->ttl;
    copy->pubId = *ackUuid;
    copy->sender = pub->ack.sender;
    memcpy(&copy->senderAddr, &pub->ack.senderAddr, sizeof(DPS_NodeAddress));
    copy->node = pub->node;
    copy->numTopics = pub->numTopics;
    if (pub->numTopics > 0) {
        size_t i;
        copy->topics = calloc(pub->numTopics, sizeof(char*));
        if (!copy->topics) {
            DPS_ERRPRINT("alloc failure: no memory\n");
            goto Exit;
        }
        for (i = 0; i < pub->numTopics; i++) {
            copy->topics[i] = strndup(pub->topics[i], DPS_MAX_TOPIC_STRLEN);
        }
    }
    ret = DPS_OK;

Exit:
    if (ret != DPS_OK) {
        DPS_DestroyCopy(copy);
        copy = NULL;
    }
    return copy;
}

static void DestroyHandlerData(HandlerData* handlerData)
{
    if (handlerData) {
        if (handlerData->service) {
            DPS_QueueRemove(&handlerData->queue);
        }
        DPS_DestroyCopy(handlerData->pub);
        if (handlerData->data) {
            free(handlerData->data);
        }
        free(handlerData);
    }
}

static HandlerData* CreateHandlerData(DPS_DiscoveryService* service, const DPS_Publication* pub,
                                      const DPS_UUID* uuid, uint8_t* payload, size_t len)
{
    HandlerData* handlerData = NULL;
    DPS_Status ret = DPS_OK;

    if (service->handler) {
        handlerData = calloc(1, sizeof(HandlerData));
        if (!handlerData) {
            DPS_ERRPRINT("alloc failure: no memory\n");
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        DPS_QueuePushBack(&service->handlerQueue, &handlerData->queue);
        handlerData->service = service;
        handlerData->pub = CopyPublication(pub, uuid);
        if (!handlerData->pub) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        if (len) {
            handlerData->data = malloc(len);
            if (!handlerData->data) {
                DPS_ERRPRINT("alloc failure: no memory\n");
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            memcpy(handlerData->data, payload, len);
            handlerData->dataLen = len;
        }
    }
Exit:
    if (ret != DPS_OK) {
        DestroyHandlerData(handlerData);
        handlerData = NULL;
    }
    return handlerData;
}

static void CallHandler(HandlerData* handlerData)
{
    if (handlerData && handlerData->service) {
        if (handlerData->service->handler) {
            handlerData->service->handler(handlerData->service, handlerData->pub,
                                          handlerData->data, handlerData->dataLen);
        }
    }
}

static void LinkCb(DPS_Node* node, const DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    if (status == DPS_OK) {
        DPS_DBGPRINT("Node is linked to %s\n", DPS_NodeAddrToString(addr));
    } else if (status != DPS_ERR_EXISTS) {
        DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(status));
    }
    CallHandler(data);
    DestroyHandlerData(data);
}

static void OnAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    DPS_Node* node = service->node;
    DPS_UUID ackUuid;
    int match;
    uint8_t* data = NULL;
    size_t dataLen = 0;
    HandlerData* handlerData = NULL;
    DPS_Status ret;

    ret = DecodeDiscoveryPayload(service, DPS_MSG_TYPE_ACK, &ackUuid, &match, &data, &dataLen,
                                 payload, len);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Decode failed - %s\n", DPS_ErrTxt(ret));
        return;
    }
    handlerData = CreateHandlerData(service, pub, &ackUuid, data, dataLen);
    if (match) {
        ret = DPS_LinkRemoteAddr(node, DPS_AckGetSenderAddress(pub), LinkCb, handlerData);
        if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    }
    if (!match || ret != DPS_OK) {
        CallHandler(handlerData);
        DestroyHandlerData(handlerData);
    }
}

static void AckCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                  void* data)
{
    DPS_Node* node = data;
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(status));
    }
    DestroyPayload(node, bufs, numBufs);
}

static void AckPublication(DPS_DiscoveryService* service, const DPS_Publication* pub)
{
    DPS_Buffer bufs[2];
    DPS_Status ret;

    if (!service) {
        return;
    }

    memset(bufs, 0, sizeof(bufs));
    ret = EncodeDiscoveryPayload(service, DPS_MSG_TYPE_ACK, bufs);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_AckPublicationBufs(pub, bufs, 2, AckCb, service->node);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }

Exit:
    if (ret != DPS_OK) {
        DestroyPayload(service->node, bufs, 2);
    }
}

static void DestroyAckRequest(AckRequest* req)
{
    DPS_Status ret;

    ret = DPS_DestroyPublication(req->pub, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_DestroyPublication failed - %s\n", DPS_ErrTxt(ret));
    }
    if (req->timer) {
        uv_close((uv_handle_t*)req->timer, TimerCloseCb);
    }
    if (req->service) {
        DPS_QueueRemove(&req->queue);
    }
    free(req);
}

static void AckTimerOnTimeout(uv_timer_t* timer)
{
    AckRequest* req = timer->data;
    AckPublication(req->service, req->pub);
    DestroyAckRequest(req);
}

static void Ack(NodeRequest* nodeReq)
{
    AckRequest* req = nodeReq->data;
    DPS_Node* node;
    uint64_t timeout;
    int err;

    if (!req->service) {
        DestroyAckRequest(req);
        return;
    }

    node = req->service->node;
    DPS_LockNode(node);
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
        DestroyAckRequest(req);
    }
    DPS_UnlockNode(node);
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
    DPS_QueuePushBack(&service->ackQueue, &req->queue);
    req->service = service;
    req->pub = DPS_CopyPublication(pub);
    if (!req->pub) {
        ret = DPS_ERR_RESOURCES;
        DPS_ERRPRINT("DPS_CopyPublication failed - %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_NodeRequestInit(node, &req->delayReq, Ack);
    req->delayReq.data = req;
    ret = DPS_NodeRequestSchedule(&req->delayReq);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_NodeScheduleRequest failed - %s\n", DPS_ErrTxt(ret));
    }
Exit:
    if (ret != DPS_OK) {
        if (req) {
            DestroyAckRequest(req);
        }
    }
    return ret;
}

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DiscoveryService* service = DPS_GetSubscriptionData(sub);
    DPS_Node* node = service->node;
    int match;
    uint8_t* data = NULL;
    size_t dataLen = 0;
    HandlerData* handlerData = NULL;
    DPS_Status ret;

    DPS_DBGTRACEA("payload len = %d%s\n", len, DPS_PublicationIsAckRequested(pub) ? " Ack requested" : "");

    if (len) {
        ret = DecodeDiscoveryPayload(service, DPS_MSG_TYPE_PUB, NULL, &match, &data, &dataLen,
                            payload, len);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Decode failed - %s\n", DPS_ErrTxt(ret));
            return;
        }
        if (match) {
            /*
             * Do not link to myself
             */
            if (DPS_UUIDCompare(DPS_PublicationGetUUID(service->pub), DPS_PublicationGetUUID(pub)) != 0) {
                if (DPS_PublicationIsAckRequested(pub)) {
                    AckPublication(service, pub);
                }
                handlerData = CreateHandlerData(service, pub, DPS_PublicationGetUUID(pub), data, dataLen);
                ret = DPS_LinkRemoteAddr(node, DPS_PublicationGetSenderAddress(pub), LinkCb, handlerData);
                if (ret != DPS_OK && ret != DPS_ERR_EXISTS) {
                    DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
                }
                if (ret != DPS_OK) {
                    DestroyHandlerData(handlerData);
                    handlerData = NULL;
                }
            }
        } else if (DPS_PublicationIsAckRequested(pub)) {
            ScheduleAck(service, pub);
        }
    } else {
        /*
         * A goodbye message, do nothing except notify the application
         */
    }
    if (!handlerData && service->handler) {
        service->handler(service, pub, data, dataLen);
    }
}

static void StartTimer(NodeRequest* req)
{
    DPS_DiscoveryService* service = req->data;
    DPS_Node* node = service->node;
    int err;

    DPS_LockNode(node);
    if (!service->timer) {
        service->timer = malloc(sizeof(uv_timer_t));
        if (!service->timer) {
            DPS_ERRPRINT("alloc failed - %s\n", DPS_ErrTxt(DPS_ERR_RESOURCES));
            goto Exit;
        }
        service->timer->data = service;
        err = uv_timer_init(node->loop, service->timer);
        if (err) {
            DPS_ERRPRINT("uv_timer_init failed - %s\n", uv_strerror(err));
            goto Exit;
        }
    } else {
        uv_timer_stop(service->timer);
    }
    service->nextTimeout = (DPS_Rand() % 100) + 20;
    err = uv_timer_start(service->timer, PublishTimerOnTimeout, service->nextTimeout, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        goto Exit;
    }
    service->nextTimeout += 1000;
Exit:
    DPS_UnlockNode(node);
    free(req);
}

DPS_Status DPS_DiscoveryPublish(DPS_DiscoveryService* service, const uint8_t* payload, size_t len,
                                DPS_DiscoveryHandler handler)
{
    SharedBuffer* buffer = NULL;
    NodeRequest* req = NULL;
    DPS_Status ret;

    DPS_DBGTRACEA("service=%p\n", service);

    if (!service) {
        return DPS_ERR_NULL;
    }
    if (len && !payload) {
        return DPS_ERR_ARGS;
    }

    service->handler = handler;
    if (!service->subscribed) {
        ret = DPS_Subscribe(service->sub, OnPub);
        if (ret != DPS_OK) {
            return ret;
        }
        service->subscribed = DPS_TRUE;
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
    req = (NodeRequest*)malloc(sizeof(NodeRequest));
    if (!req) {
        DPS_ERRPRINT("Failed to allocate request - %s\n", DPS_ErrTxt(ret));
        return DPS_ERR_RESOURCES;
    }
    DPS_NodeRequestInit(service->node, req, StartTimer);
    req->data = service;
    ret = DPS_NodeRequestSchedule(req);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start discovery - %s\n", DPS_ErrTxt(ret));
        free(req);
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
        /*
         * handlerData will be freed via already pending callbacks,
         * but LinkCb may run after service is destroyed.
         */
        DPS_Queue* queue;
        for (queue = &service->handlerQueue; queue->next != &service->handlerQueue; queue = queue->next) {
            HandlerData* handlerData = (HandlerData*)queue->next;
            handlerData->service = NULL;
        }
        for (queue = &service->ackQueue; queue->next != &service->ackQueue; queue = queue->next) {
            AckRequest* req = (AckRequest*)queue->next;
            req->service = NULL;
        }
        SharedBufferDecRef(service->payload);
        if (service->topic) {
            free(service->topic);
        }
        service->destroyCb(service, service->destroyData);
        free(service);
    }
}

static void DestroyService(NodeRequest* req)
{
    DPS_DiscoveryService* service = req->data;
    DPS_Node* node = service->node;
    DPS_LockNode(node);
    Destroy(service);
    DPS_UnlockNode(node);
    free(req);
}

static void PublishDestroyCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs,
                             DPS_Status status, void* data)
{
    DPS_DiscoveryService* service = DPS_GetPublicationData(pub);
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(status));
    }
    Destroy(service);
}

DPS_Status DPS_DestroyDiscoveryService(DPS_DiscoveryService* service,
                                       DPS_OnDiscoveryServiceDestroyed cb, void* data)
{
    NodeRequest* req = NULL;
    DPS_Status ret;

    DPS_DBGTRACEA("service=%p,cb=%p,data=%p\n", service, cb, data);

    if (!service || !cb) {
        return DPS_ERR_NULL;
    }
    service->destroyCb = cb;
    service->destroyData = data;
    /*
     * Publish a goodbye message, then destroy the service
     */
    ret = DPS_PublishBufs(service->pub, NULL, 0, 0, PublishDestroyCb, service);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(ret));
        req = (NodeRequest*)malloc(sizeof(NodeRequest));
        if (!req) {
            DPS_ERRPRINT("Failed to allocate request - %s\n", DPS_ErrTxt(ret));
            return DPS_ERR_RESOURCES;
        }
        DPS_NodeRequestInit(service->node, req, DestroyService);
        req->data = service;
        ret = DPS_NodeRequestSchedule(req);
        if (ret != DPS_OK) {
            free(req);
        }
    }
    return ret;
}
