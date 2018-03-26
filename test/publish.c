/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define ERREXIT() do { DPS_ERRPRINT("%s:%d\n", __FILE__, __LINE__); exit(EXIT_FAILURE); } while (0)

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static DPS_Publication* CreatePublication(DPS_Node* node, const char** topics, size_t numTopics)
{
    DPS_Publication* pub = NULL;
    DPS_Status ret;

    pub = DPS_CreatePublication(node);
    if (!pub) {
        ERREXIT();
    }
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, NULL, NULL);
    if (ret != DPS_OK) {
        ERREXIT();
    }
    return pub;
}

static void LoopbackLargeMessageHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Event* event = (DPS_Event*)DPS_GetSubscriptionData(sub);
    DPS_SignalEvent(event, DPS_OK);
}

static void LoopbackLargeMessage(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    static const uint8_t largeMessage[128*1024] = { 0 };
    DPS_Publication* pub = NULL;
    DPS_Event* event = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Status ret;
    size_t n;

    DPS_PRINT("%s\n", __FUNCTION__);

    pub = CreatePublication(node, topics, numTopics);

    event = DPS_CreateEvent();
    if (!event) {
        ERREXIT();
    }
    sub = DPS_CreateSubscription(node, topics, numTopics);
    if (!sub) {
        ERREXIT();
    }
    ret = DPS_SetSubscriptionData(sub, event);
    if (ret != DPS_OK) {
        ERREXIT();
    }
    ret = DPS_Subscribe(sub, LoopbackLargeMessageHandler);
    if (ret != DPS_OK) {
        ERREXIT();
    }

    ret = DPS_Publish(pub, largeMessage, A_SIZEOF(largeMessage), 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_Publish - %s\n", DPS_ErrTxt(ret));
        ERREXIT();
    }
    /*
     * We expect the large message to be dropped by the network layer
     * as it exceeds the maximum UDP datagram size.  But it should be
     * looped back to the local subscriber.
     */
    ret = DPS_WaitForEvent(event);
    if (ret != DPS_OK) {
        ERREXIT();
    }

    DPS_DestroyEvent(event);
    DPS_DestroySubscription(sub);
    DPS_DestroyPublication(pub);
}

int main(int argc, char** argv)
{
    DPS_Event* event = NULL;
    DPS_Node *node = NULL;
    DPS_Publication* pub = NULL;
    DPS_Status ret;

    DPS_Debug = 0;

    event = DPS_CreateEvent();
    if (!event) {
        return EXIT_FAILURE;
    }

    node = DPS_CreateNode("/.", NULL, NULL);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV, 0);
    if (ret != DPS_OK) {
        ERREXIT();
    }

    LoopbackLargeMessage(node);

    DPS_DestroyNode(node, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
    return EXIT_SUCCESS;
}
