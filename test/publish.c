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
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include "test.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static DPS_Publication* CreatePublication(DPS_Node* node, const char** topics, size_t numTopics,
                                          DPS_AcknowledgementHandler handler)
{
    DPS_Publication* pub = NULL;
    DPS_Status ret;

    pub = DPS_CreatePublication(node);
    ASSERT(pub);
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, NULL, handler);
    ASSERT(ret == DPS_OK);
    return pub;
}

static void TestCreateDestroy(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Publication* pub = NULL;
    DPS_Status ret;

    DPS_PRINT("%s\n", __FUNCTION__);

    pub = DPS_CreatePublication(node);
    ASSERT(pub);
    ret = DPS_DestroyPublication(pub);
    ASSERT(ret == DPS_OK);

    pub = DPS_CreatePublication(node);
    ASSERT(pub);
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, NULL, NULL);
    ASSERT(ret == DPS_OK);
    ret = DPS_DestroyPublication(pub);
    ASSERT(ret == DPS_OK);
}

static void LoopbackLargeMessageHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Event* event = (DPS_Event*)DPS_GetSubscriptionData(sub);
    DPS_SignalEvent(event, DPS_OK);
}

static void TestLoopbackLargeMessage(DPS_Node* node)
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

    pub = CreatePublication(node, topics, numTopics, NULL);

    event = DPS_CreateEvent();
    ASSERT(event);
    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    ret = DPS_SetSubscriptionData(sub, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, LoopbackLargeMessageHandler);
    ASSERT(ret == DPS_OK);

    ret = DPS_Publish(pub, largeMessage, A_SIZEOF(largeMessage), 0);
    ASSERT(ret == DPS_OK);
    /*
     * We expect the large message to be dropped by the network layer
     * as it exceeds the maximum UDP datagram size.  But it should be
     * looped back to the local subscriber.
     */
    ret = DPS_WaitForEvent(event);
    ASSERT(ret == DPS_OK);

    DPS_DestroyEvent(event);
    DPS_DestroySubscription(sub);
    DPS_DestroyPublication(pub);
}

static void LoopbackAckMessageHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    int* receivedMessage = (int*)DPS_GetSubscriptionData(sub);
    DPS_Status ret;

    *receivedMessage = DPS_TRUE;
    ret = DPS_AckPublication(pub, NULL, 0);
    ASSERT(ret == DPS_OK);
}

static void LoopbackAckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Event* event = (DPS_Event*)DPS_GetPublicationData(pub);
    DPS_SignalEvent(event, DPS_OK);
}

static void LoopbackAckLargeMessageHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    static const uint8_t largeMessage[128*1024] = { 0 };
    int* receivedMessage = (int*)DPS_GetSubscriptionData(sub);
    DPS_Status ret;

    *receivedMessage = DPS_TRUE;
    ret = DPS_AckPublication(pub, largeMessage, A_SIZEOF(largeMessage));
    ASSERT(ret == DPS_OK);
}

static void TestLoopbackAckLargeMessage(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    static const uint8_t message[8*1024] = { 0 };
    DPS_Publication* pub = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Event* event = NULL;
    int receivedMessage = DPS_FALSE;
    DPS_Event* ackEvent = NULL;
    DPS_Status ret;
    size_t n;

    DPS_PRINT("%s\n", __FUNCTION__);

    pub = CreatePublication(node, topics, numTopics, LoopbackAckHandler);
    ackEvent = DPS_CreateEvent();
    ASSERT(ackEvent);
    ret = DPS_SetPublicationData(pub, ackEvent);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    ret = DPS_SetSubscriptionData(sub, &receivedMessage);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, LoopbackAckLargeMessageHandler);
    ASSERT(ret == DPS_OK);

    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_Publish(pub, message, A_SIZEOF(message), 0);
    ASSERT(ret == DPS_OK);
    ret = DPS_WaitForEvent(ackEvent);
    ASSERT(ret == DPS_OK);

    DPS_DestroyEvent(event);
    DPS_DestroySubscription(sub);
    DPS_DestroyEvent(ackEvent);
    DPS_DestroyPublication(pub);
}

#define HISTORY_CAP 10

static DPS_Publication* pubs[HISTORY_CAP + 1];

static void HistoryHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Event* event = (DPS_Event*)DPS_GetSubscriptionData(sub);
    uint32_t sequenceNum = DPS_PublicationGetSequenceNum(pub);

    pubs[sequenceNum] = DPS_CopyPublication(pub);

    DPS_SignalEvent(event, DPS_OK);
}

static void HistoryAckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_Event* event = (DPS_Event*)DPS_GetPublicationData(pub);
    DPS_SignalEvent(event, DPS_OK);
}

static void TestHistory(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Event* event = NULL;
    DPS_Publication* pub = NULL;
    DPS_QoS qos;
    DPS_Event* ackEvent = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Status ret;
    size_t i;

    DPS_PRINT("%s\n", __FUNCTION__);

    memset(pubs, 0, A_SIZEOF(pubs));

    pub = CreatePublication(node, topics, numTopics, HistoryAckHandler);
    qos.historyDepth = HISTORY_CAP;
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    ASSERT(ret == DPS_OK);
    ackEvent = DPS_CreateEvent();
    ASSERT(ackEvent);
    ret = DPS_SetPublicationData(pub, ackEvent);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_SetSubscriptionData(sub, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, HistoryHandler);
    ASSERT(ret == DPS_OK);

    for (i = 0; i < HISTORY_CAP; ++i) {
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
        ret = DPS_WaitForEvent(event);
        ASSERT(ret == DPS_OK);
    }

    for (i = 0; i < HISTORY_CAP; ++i) {
        ret = DPS_AckPublication(pubs[i + 1], NULL, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pubs[i + 1]);
        ret = DPS_WaitForEvent(ackEvent);
        ASSERT(ret == DPS_OK);
    }

    DPS_DestroySubscription(sub);
    DPS_DestroyEvent(event);
    DPS_DestroyPublication(pub);
    DPS_DestroyEvent(ackEvent);
}

static void TestHistoryDepth(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Event* event = NULL;
    DPS_Publication* pub = NULL;
    DPS_QoS qos;
    DPS_Event* ackEvent = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Status ret;
    size_t i;

    DPS_PRINT("%s\n", __FUNCTION__);

    memset(pubs, 0, A_SIZEOF(pubs));

    pub = CreatePublication(node, topics, numTopics, HistoryAckHandler);
    qos.historyDepth = HISTORY_CAP / 2;
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    ASSERT(ret == DPS_OK);
    ackEvent = DPS_CreateEvent();
    ASSERT(ackEvent);
    ret = DPS_SetPublicationData(pub, ackEvent);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_SetSubscriptionData(sub, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, HistoryHandler);
    ASSERT(ret == DPS_OK);

    for (i = 0; i < HISTORY_CAP; ++i) {
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
        ret = DPS_WaitForEvent(event);
        ASSERT(ret == DPS_OK);
    }
    /* Sequence numbers 6..10 are now in the history */

    /*
     * Ack everything but only expect ack for 6..10 to be received
     * since the older ones were removed from the history
     */
    for (i = 0; i < HISTORY_CAP / 2; ++i) {
        ret = DPS_AckPublication(pubs[i + 1], NULL, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pubs[i + 1]);
        ret = DPS_TimedWaitForEvent(ackEvent, 100);
        ASSERT(ret == DPS_ERR_TIMEOUT);
    }
    for (; i < HISTORY_CAP; ++i) {
        ret = DPS_AckPublication(pubs[i + 1], NULL, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pubs[i + 1]);
        ret = DPS_WaitForEvent(ackEvent);
        ASSERT(ret == DPS_OK);
    }

    DPS_DestroySubscription(sub);
    DPS_DestroyEvent(event);
    DPS_DestroyPublication(pub);
    DPS_DestroyEvent(ackEvent);
}

static void TestOutOfOrderAck(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Event* event = NULL;
    DPS_Publication* pub = NULL;
    DPS_QoS qos;
    DPS_Event* ackEvent = NULL;
    DPS_Subscription* sub = NULL;
    DPS_Status ret;
    size_t i;

    DPS_PRINT("%s\n", __FUNCTION__);

    memset(pubs, 0, A_SIZEOF(pubs));

    pub = CreatePublication(node, topics, numTopics, HistoryAckHandler);
    qos.historyDepth = HISTORY_CAP / 2;
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    ASSERT(ret == DPS_OK);
    ackEvent = DPS_CreateEvent();
    ASSERT(ackEvent);
    ret = DPS_SetPublicationData(pub, ackEvent);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    event = DPS_CreateEvent();
    ASSERT(event);
    ret = DPS_SetSubscriptionData(sub, event);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, HistoryHandler);
    ASSERT(ret == DPS_OK);

    for (i = 0; i < HISTORY_CAP; ++i) {
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
        ret = DPS_WaitForEvent(event);
        ASSERT(ret == DPS_OK);
    }

    for (i = HISTORY_CAP; i > HISTORY_CAP / 2; --i) {
        ret = DPS_AckPublication(pubs[i], NULL, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pubs[i]);
        ret = DPS_WaitForEvent(ackEvent);
        ASSERT(ret == DPS_OK);
    }
    for (; i > 0; --i) {
        ret = DPS_AckPublication(pubs[i], NULL, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pubs[i]);
        ret = DPS_TimedWaitForEvent(ackEvent, 100);
        ASSERT(ret == DPS_ERR_TIMEOUT);
    }

    DPS_DestroySubscription(sub);
    DPS_DestroyEvent(event);
    DPS_DestroyPublication(pub);
    DPS_DestroyEvent(ackEvent);
}

static void BackToBackPublishHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    uint32_t* expectedSequenceNum = (uint32_t*)DPS_GetSubscriptionData(sub);
    uint32_t sequenceNum = DPS_PublicationGetSequenceNum(pub);

    ASSERT(sequenceNum == *expectedSequenceNum);
    ++(*expectedSequenceNum);
}

static void TestBackToBackPublish(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Publication* pub = NULL;
    size_t depth = 10000;
    DPS_QoS qos;
    DPS_Subscription* sub = NULL;
    uint32_t seqNum;
    DPS_Status ret;
    size_t i;

    DPS_PRINT("%s\n", __FUNCTION__);

    pub = CreatePublication(node, topics, numTopics, NULL);
    qos.historyDepth = depth;
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(node, topics, numTopics);
    ASSERT(sub);
    ret = DPS_SetSubscriptionData(sub, &seqNum);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, BackToBackPublishHandler);
    ASSERT(ret == DPS_OK);

    seqNum = DPS_PublicationGetSequenceNum(pub) + 1;
    for (i = 0; i < depth; ++i) {
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
    }

    /*
     * Give some time to receive the publications since we don't
     * explicitly wait for the acks in this test.
     */
    SLEEP(1000);

    DPS_DestroySubscription(sub);
    DPS_DestroyPublication(pub);
}

static void TestBackToBackPublishSeparateNodes(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Publication* pub = NULL;
    size_t depth = 10000;
    DPS_QoS qos;
    DPS_Event* event = NULL;
    DPS_Node* subNode = NULL;
    DPS_Subscription* sub = NULL;
    uint32_t seqNum;
    DPS_Status ret;
    size_t i;

    DPS_PRINT("%s\n", __FUNCTION__);

    pub = CreatePublication(node, topics, numTopics, NULL);
    qos.historyDepth = depth;
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    ASSERT(ret == DPS_OK);

    event = DPS_CreateEvent();
    ASSERT(event);

    subNode = DPS_CreateNode("/.", NULL, NULL);
    ASSERT(subNode);
    ret = DPS_StartNode(subNode, DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV, 0);
    ASSERT(ret == DPS_OK);

    sub = DPS_CreateSubscription(subNode, topics, numTopics);
    ASSERT(sub);
    ret = DPS_SetSubscriptionData(sub, &seqNum);
    ASSERT(ret == DPS_OK);
    ret = DPS_Subscribe(sub, BackToBackPublishHandler);
    ASSERT(ret == DPS_OK);

    seqNum = DPS_PublicationGetSequenceNum(pub) + 1;
    for (i = 0; i < depth; ++i) {
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
    }

    /*
     * Give some time to receive the publications since we don't
     * explicitly wait for the acks in this test.
     */
    SLEEP(1000);

    DPS_DestroySubscription(sub);
    DPS_DestroyNode(subNode, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
    DPS_DestroyPublication(pub);
}

static void TestRetainedMessage(DPS_Node* node)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    DPS_Publication* pub = NULL;
    size_t depth;
    DPS_QoS qos;
    DPS_Status ret;

    DPS_PRINT("%s\n", __FUNCTION__);

    for (depth = 1; depth <= 2; ++depth) {
        qos.historyDepth = depth;

        pub = CreatePublication(node, topics, numTopics, NULL);
        ret = DPS_PublicationConfigureQoS(pub, &qos);
        ASSERT(ret == DPS_OK);
        ret = DPS_Publish(pub, NULL, 0, -1);
        ASSERT(ret == DPS_ERR_INVALID);
        DPS_DestroyPublication(pub);

        pub = CreatePublication(node, topics, numTopics, NULL);
        ret = DPS_PublicationConfigureQoS(pub, &qos);
        ASSERT(ret == DPS_OK);
        ret = DPS_Publish(pub, NULL, 0, 10);
        if (depth == 1) {
            ASSERT(ret == DPS_OK);
        } else {
            ASSERT(ret == DPS_ERR_INVALID);
        }
        ret = DPS_Publish(pub, NULL, 0, 0);
        ASSERT(ret == DPS_OK);
        DPS_DestroyPublication(pub);

        pub = CreatePublication(node, topics, numTopics, NULL);
        ret = DPS_PublicationConfigureQoS(pub, &qos);
        ASSERT(ret == DPS_OK);
        ret = DPS_Publish(pub, NULL, 0, 10);
        if (depth == 1) {
            ASSERT(ret == DPS_OK);
        } else {
            ASSERT(ret == DPS_ERR_INVALID);
        }
        ret = DPS_Publish(pub, NULL, 0, -1);
        if (depth == 1) {
            ASSERT(ret == DPS_OK);
        } else {
            ASSERT(ret == DPS_ERR_INVALID);
        }
        DPS_DestroyPublication(pub);
    }
}

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    DPS_Event* event = NULL;
    DPS_Node *node = NULL;
    DPS_Publication* pub = NULL;
    DPS_Status ret;

    DPS_Debug = 0;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
        }
    }

    event = DPS_CreateEvent();
    ASSERT(event);

    node = DPS_CreateNode("/.", NULL, NULL);
    ASSERT(node);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV, 0);
    ASSERT(ret == DPS_OK);

    TestCreateDestroy(node);
    TestLoopbackLargeMessage(node);
    TestLoopbackAckLargeMessage(node);
    TestHistory(node);
    TestHistoryDepth(node);
    TestOutOfOrderAck(node);
    TestBackToBackPublish(node);
    TestBackToBackPublishSeparateNodes(node);
    TestRetainedMessage(node);

    DPS_DestroyNode(node, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
    /*
     * For clean valgrind results, wait for node thread to exit
     * completely.
     */
    SLEEP(10);
    return EXIT_SUCCESS;
}
