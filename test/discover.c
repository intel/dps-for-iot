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

#include "test.h"
#include <stdio.h>
#include <uv.h>
#include "node.h"

typedef struct _DiscoveryService {
    DPS_Node* node;
    DPS_Publication* pub;
    DPS_Subscription* sub;
    uv_timer_t* timer;
    uint64_t nextTimeout;
} DiscoveryService;

static void DiscoveryPublishCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                               void* data)
{
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_PublishBufs failed - %s\n", DPS_ErrTxt(status));
    }
    free(bufs[0].base);
}

static void DiscoveryAckCb(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status,
                           void* data)
{
    if (status != DPS_OK) {
        DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(status));
    }
    free(bufs[0].base);
}

static void DiscoveryTimerOnTimeout(uv_timer_t* timer)
{
    DiscoveryService* service = timer->data;
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

static void DiscoveryTimerCloseCb(uv_handle_t* timer)
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
    DiscoveryService* service = DPS_GetPublicationData(pub);
    DPS_Node* node = service->node;
    DPS_Buffer remoteSubs;
    DPS_Status ret;

    remoteSubs.base = payload;
    remoteSubs.len = len;
    if (DPS_MatchPublications(node, &remoteSubs)) {
        ret = DPS_Link(node, DPS_NodeAddrToString(DPS_AckGetSenderAddress(pub)), DiscoveryLinkCb, service);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void DiscoveryOnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DiscoveryService* service = DPS_GetSubscriptionData(sub);
    DPS_Node* node = service->node;
    DPS_Buffer remoteSubs;
    DPS_Buffer subs;
    DPS_Status ret;

    /* Ignore my own publication */
    if (DPS_UUIDCompare(DPS_PublicationGetUUID(service->pub), DPS_PublicationGetUUID(pub)) == 0) {
        return;
    }

    memset(&subs, 0, sizeof(DPS_Buffer));
    remoteSubs.base = payload;
    remoteSubs.len = len;
    if (DPS_MatchPublications(node, &remoteSubs)) {
        ret = DPS_Link(node, DPS_NodeAddrToString(DPS_PublicationGetSenderAddress(pub)), DiscoveryLinkCb,
                       service);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_Link failed - %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
    } else if (DPS_PublicationIsAckRequested(pub)) {
        ret = DPS_SerializeSubscriptions(node, &subs);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_SerializeSubscriptions failed - %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
        ret = DPS_AckPublicationBufs(pub, &subs, 1, DiscoveryAckCb, service);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_AckPublicationBufs failed - %s\n", DPS_ErrTxt(ret));
            goto Exit;
        }
    } else {
        ret = DPS_OK;
    }
Exit:
    if (ret != DPS_OK) {
        if (subs.base) {
            free(subs.base);
        }
    }
}

void DiscoveryStop(DiscoveryService* service);

static void DiscoveryStartTimer(void* data)
{
    DiscoveryService* service = data;
    DPS_Node* node = service->node;
    int err;

    service->timer = malloc(sizeof(uv_timer_t));
    if (!service->timer) {
        DPS_ERRPRINT("malloc failed - %s\n", DPS_ErrTxt(DPS_ERR_RESOURCES));
        return;
    }
    service->timer->data = service;
    err = uv_timer_init(node->loop, service->timer);
    if (err) {
        DPS_ERRPRINT("uv_timer_init failed - %s\n", uv_strerror(err));
        return;
    }
    err = uv_timer_start(service->timer, DiscoveryTimerOnTimeout, 0, 0);
    if (err) {
        DPS_ERRPRINT("uv_timer_start failed - %s\n", uv_strerror(err));
        return;
    }
    service->nextTimeout = 1000;
}

static void DiscoveryStopTimer(void* data)
{
    uv_handle_t* timer = data;
    uv_close(timer, DiscoveryTimerCloseCb);
}

int DiscoveryStart(DiscoveryService* service, DPS_Node* node)
{
    static const char *topic = "$DPS/node";
    DPS_Status ret;

    memset(service, 0, sizeof(DiscoveryService));
    service->node = node;
    service->pub = DPS_CreatePublication(node);
    if (!service->pub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetPublicationData(service->pub, service);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_InitPublication(service->pub, &topic, 1, DPS_FALSE, NULL, DiscoveryOnAck);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_PublicationSetMulticast(service->pub, DPS_TRUE);
    if (ret != DPS_OK) {
        goto Exit;
    }
    service->sub = DPS_CreateSubscription(node, &topic, 1);
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
    ret = DPS_NodeScheduleRequest(node, DiscoveryStartTimer, service);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    if (ret != DPS_OK) {
        DiscoveryStop(service);
    }
    return ret;
}

void DiscoveryStop(DiscoveryService* service)
{
    if (service->timer) {
        DPS_NodeScheduleRequest(service->node, DiscoveryStopTimer, service->timer);
        service->timer = NULL;
    }
    DPS_DestroySubscription(service->sub);
    DPS_DestroyPublication(service->pub);
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent((DPS_Event*)data, DPS_OK);
}

typedef struct _PublicationList {
    char* topic;
    DPS_Publication* pub;
    struct _PublicationList* next;
} PublicationList;

typedef struct _SubscriptionList {
    char* topic;
    DPS_Subscription* sub;
    struct _SubscriptionList* next;
} SubscriptionList;

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    PublicationList* pubs = NULL;
    SubscriptionList* subs = NULL;
    DPS_Event* event = NULL;
    DPS_Node* node = NULL;
    PublicationList* pub;
    SubscriptionList* sub;
    DiscoveryService discovery;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
        } else if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            pub = calloc(1, sizeof(PublicationList));
            if (!pub) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            pub->topic = strdup(*arg);
            if (!pub->topic) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            pub->next = pubs;
            pubs = pub;
            ++arg;
        } else if (strcmp(*arg, "-s") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            sub = calloc(1, sizeof(SubscriptionList));
            if (!sub) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            sub->topic = strdup(*arg);
            if (!sub->topic) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            sub->next = subs;
            subs = sub;
            ++arg;
        } else {
            goto Usage;
        }
    }

    event = DPS_CreateEvent();
    if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    node = DPS_CreateNode("/", NULL, NULL);
    if (!node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_RECV, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_PRINT("Node is listening on %s\n", DPS_GetListenAddressString(node));
    for (pub = pubs; pub; pub = pub->next) {
        pub->pub = DPS_CreatePublication(node);
        if (!pub->pub) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_InitPublication(pub->pub, (const char**)&pub->topic, 1, DPS_FALSE, NULL, NULL);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    for (sub = subs; sub; sub = sub->next) {
        sub->sub = DPS_CreateSubscription(node, (const char**)&sub->topic, 1);
        if (!sub->sub) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_Subscribe(sub->sub, OnPub);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    ret = DiscoveryStart(&discovery, node);
    if (ret != DPS_OK) {
        goto Exit;
    }

    getc(stdin);

Exit:
    DiscoveryStop(&discovery);
    while (subs) {
        sub = subs;
        subs = subs->next;
        if (sub->topic) {
            free(sub->topic);
        }
        DPS_DestroySubscription(sub->sub);
        free(sub);
    }
    while (pubs) {
        pub = pubs;
        pubs = pubs->next;
        if (pub->topic) {
            free(pub->topic);
        }
        DPS_DestroyPublication(pub->pub);
        free(pub);
    }
    if (node) {
        DPS_DestroyNode(node, OnNodeDestroyed, event);
        DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
    return ret;

Usage:
    DPS_PRINT("Usage %s [-d] [-p topic] [-s topic]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -p: Publish to topic. Multiple -p options are permitted.\n");
    DPS_PRINT("       -s: Subscribe to topic. Multiple -s options are permitted.\n");
    return DPS_ERR_FAILURE;
}
