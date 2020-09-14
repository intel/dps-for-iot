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

#include <stdio.h>
#include <dps/discovery.h>
#include "compat.h"
#include "keys.h"
#include "node.h"
#include "test.h"
#include "topics.h"

#define MAX_MSG_LEN 128

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent((DPS_Event*)data, DPS_OK);
}

static void OnDiscoveryServiceDestroyed(DPS_DiscoveryService* service, void* data)
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
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    const DPS_KeyId* senderId = DPS_PublicationGetSenderKeyId(pub);
    size_t i;
    size_t numTopics;

    DPS_PRINT("Pub %s(%d) [%s] matches:\n", DPS_UUIDToString(pubId), sn, KeyIdToString(senderId));
    DPS_PRINT("  pub ");
    numTopics = DPS_PublicationGetNumTopics(pub);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" | ");
        }
        DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
    }
    DPS_PRINT("\n");
    DPS_PRINT("  sub ");
    numTopics = DPS_SubscriptionGetNumTopics(sub);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" & ");
        }
        DPS_PRINT("%s", DPS_SubscriptionGetTopic(sub, i));
    }
    DPS_PRINT("\n");
    if (payload) {
        DPS_PRINT("%.*s\n", (int)len, payload);
    }
}

static PublicationList* pubList = NULL;
static int ttl = 0;

static void OnDiscovery(DPS_DiscoveryService* service, const DPS_Publication* pub,
                        uint8_t* payload, size_t len)
{
    static const char msg[] = "Hello from discovery service";
    PublicationList* pubs;
    DPS_Status ret;
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);

    DPS_PRINT("Discovered %s(%d) %s\n", DPS_UUIDToString(pubId), sn, payload);

    for (pubs = pubList; pubs; pubs = pubs->next) {
        ret = DPS_Publish(pubs->pub, (uint8_t*)msg, sizeof(msg), ttl); 
        ASSERT(ret == DPS_OK);
    }
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    SubscriptionList* subs = NULL;
    DPS_Event* event = NULL;
    DPS_Node* node = NULL;
    PublicationList* pubs;
    SubscriptionList* sub;
    DPS_DiscoveryService* discovery = NULL;
    char* msg = NULL;
    DPS_Status ret;
    int noWildCard = DPS_FALSE;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
        } else if (strcmp(*arg, "-w") == 0) {
            ++arg;
            noWildCard = DPS_TRUE;
        } else if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            pubs = calloc(1, sizeof(PublicationList));
            if (!pubs) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            pubs->topic = strndup(*arg, DPS_MAX_TOPIC_STRLEN);
            if (!pubs->topic) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            pubs->next = pubList;
            pubList = pubs;
            ++arg;
        } else if (IntArg("-t", &arg, &argc, &ttl, 0, 1000)) {
            continue;
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
            sub->topic = strndup(*arg, DPS_MAX_TOPIC_STRLEN);
            if (!sub->topic) {
                ret = DPS_ERR_RESOURCES;
                goto Exit;
            }
            sub->next = subs;
            subs = sub;
            ++arg;
        } else if (strcmp(*arg, "-m") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            msg = *arg++;
            continue;
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
    for (pubs = pubList; pubs; pubs = pubs->next) {
        pubs->pub = DPS_CreatePublication(node);
        if (!pubs->pub) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_InitPublication(pubs->pub, (const char**)&pubs->topic, 1, noWildCard, NULL);
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
    /*
     * Speed up the subscription rate so the test case runs faster
     * when used with a large node population.
     */
    node->subsRate = 250;
    discovery = DPS_CreateDiscoveryService(node, "test");
    ret = DPS_DiscoveryPublish(discovery, (uint8_t*)msg, msg ? strnlen(msg, MAX_MSG_LEN) + 1 : 0,
                               OnDiscovery);
    if (ret != DPS_OK) {
        goto Exit;
    }

    getc(stdin);

Exit:

    if (ret != DPS_OK) {
        DPS_ERRPRINT("Exiting: %s\n", DPS_ErrTxt(ret));
    }

    DPS_DestroyDiscoveryService(discovery, OnDiscoveryServiceDestroyed, event);
    DPS_WaitForEvent(event);

    while (subs) {
        sub = subs;
        subs = subs->next;
        if (sub->topic) {
            free(sub->topic);
        }
        DPS_DestroySubscription(sub->sub, NULL);
        free(sub);
    }
    while (pubList) {
        pubs = pubList;
        pubList = pubList->next;
        if (pubs->topic) {
            free(pubs->topic);
        }
        DPS_DestroyPublication(pubs->pub, NULL);
        free(pubs);
    }
    if (node) {
        DPS_DestroyNode(node, OnNodeDestroyed, event);
        DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
    return ret;

Usage:
    DPS_PRINT("Usage %s [-d] [-w] [-p topic] [-s topic]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -w: Do not match wildcard subscriptions.\n");
    DPS_PRINT("       -p: Publish to topic. Multiple -p options are permitted.\n");
    DPS_PRINT("       -s: Subscribe to topic. Multiple -s options are permitted.\n");
    return DPS_ERR_FAILURE;
}
