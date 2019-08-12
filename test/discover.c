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
#include "topics.h"
#include <dps/discovery.h>

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

static void OnDiscovery(DPS_DiscoveryService* service, uint8_t* payload, size_t len)
{
    DPS_PRINT("%s\n", payload);
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
    DPS_DiscoveryService* discovery = NULL;
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
            pub->topic = strndup(*arg, DPS_MAX_TOPIC_STRLEN);
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
            sub->topic = strndup(*arg, DPS_MAX_TOPIC_STRLEN);
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
    discovery = DPS_CreateDiscoveryService(node, "test");
    ret = DPS_DiscoveryPublish(discovery, (const uint8_t*)"hello", 6, OnDiscovery);
    if (ret != DPS_OK) {
        goto Exit;
    }

    getc(stdin);

Exit:

    if (ret != DPS_OK) {
        DPS_ERRPRINT("Exiting: %s\n", DPS_ErrTxt(ret));
    }

    DPS_DestroyDiscoveryService(discovery);

    while (subs) {
        sub = subs;
        subs = subs->next;
        if (sub->topic) {
            free(sub->topic);
        }
        DPS_DestroySubscription(sub->sub, NULL);
        free(sub);
    }
    while (pubs) {
        pub = pubs;
        pubs = pubs->next;
        if (pub->topic) {
            free(pub->topic);
        }
        DPS_DestroyPublication(pub->pub, NULL);
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
