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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/event.h>
/** [Prerequisites] */
#include <dps/dbg.h>
#include <dps/dps.h>
/** [Prerequisites] */

#ifdef _WIN32
#define SLEEP(t) Sleep(t)
#else
extern void usleep(int);
#define SLEEP(t) usleep((t) * 1000)
#endif

static DPS_Status StartMulticastNode(DPS_Node* node);
static DPS_Status StartUnicastNode(DPS_Node* node, int listenPort);
static void LinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data);
static DPS_Status Publish(DPS_Node* node, DPS_Publication** createdPub);
static DPS_Status PublishAck(DPS_Node* node, DPS_Publication** createdPub);
static DPS_Status Subscribe(DPS_Node* node, DPS_Subscription** createdSub);
static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t len);
static void AcknowledgementHandler(DPS_Publication* pub,
                                   uint8_t* payload, size_t len);
static void DestroyNode(DPS_Node* node);

static int Usage(int argc, char** argv)
{
    DPS_PRINT("Usage %s [-d] [-l <port>] [-p <port>] [publish|subscribe] [ack]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -l: port to listen on.  This may be 0 to request an ephemeral port.\n");
    DPS_PRINT("       -p: port to link to.\n");
}

int main(int argc, char** argv)
{
    DPS_Publication* pub = NULL;
    DPS_Subscription* sub = NULL;
    int publish = DPS_FALSE;
    int subscribe = DPS_FALSE;
    int ack = DPS_FALSE;
    int listenPort = -1;
    int linkPort = 0;
    int i;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "publish")) {
            publish = DPS_TRUE;
        } else if (!strcmp(argv[i], "subscribe")) {
            subscribe = DPS_TRUE;
        } else if (!strcmp(argv[i], "ack")) {
            ack = DPS_TRUE;
        } else if (!strcmp(argv[i], "-l") && ((i + 1) < argc)) {
            listenPort = atoi(argv[i + 1]);
            ++i;
        } else if (!strcmp(argv[i], "-p") && ((i + 1) < argc)) {
            linkPort = atoi(argv[i + 1]);
            ++i;
        } else if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        } else {
            Usage(argc, argv);
            return EXIT_FAILURE;
        }
    }

    /** [Creating a node] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = NULL;
    const DPS_KeyId* keyId = NULL;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a node] */

    if (linkPort || (listenPort >= 0)) {
        if (listenPort == -1) {
            listenPort = 0;
        }
        ret = StartUnicastNode(node, listenPort);
    } else {
        ret = StartMulticastNode(node);
    }
    if (ret != DPS_OK) {
        goto Exit;
    }

    if (linkPort) {
        /** [Linking to a node] */
        DPS_NodeAddress* addr = DPS_CreateAddress();
        if (!addr) {
            goto Exit;
        }

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(linkPort);
        saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        DPS_SetAddress(addr, (const struct sockaddr*)&saddr);

        ret = DPS_Link(node, addr, LinkComplete, NULL);
        DPS_DestroyAddress(addr);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /** [Linking to a node] */
        /* Wait for link to complete */
        SLEEP(1);
    }

    if (publish && ack) {
        ret = PublishAck(node, &pub);
    } else if (publish) {
        ret = Publish(node, &pub);
    } else if (subscribe) {
        ret = Subscribe(node, &sub);
    }
    if (ret != DPS_OK) {
        goto Exit;
    }

    /* Sleep until user kills us */
    for (;;) {
        SLEEP(1);
    }

Exit:
    DPS_DestroyPublication(pub);
    DPS_DestroySubscription(sub);
    DestroyNode(node);
    return EXIT_SUCCESS;
}

static DPS_Status StartMulticastNode(DPS_Node* node)
{
    /** [Starting a node] */
    int mcastPub = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    int listenPort = 0;
    DPS_Status ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Starting a node] */

 Exit:
    return ret;
}

static DPS_Status StartUnicastNode(DPS_Node* node, int port)
{
    /** [Starting a unicast node] */
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    int listenPort = port;
    DPS_Status ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        goto Exit;
    }
    uint16_t portNum = DPS_GetPortNumber(node);
    /** [Starting a unicast node] */
    DPS_PRINT("port=%d\n", portNum);

 Exit:
    return ret;
}

/** [Linking complete] */
static void LinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    DPS_PRINT("Linked to %s\n", DPS_NodeAddrToString(addr));
}
/** [Linking complete] */

static DPS_Status SendPublication(DPS_Publication* pub)
{
    DPS_Status ret;

    /** [Sending a publication] */
    const char* payload = "Hello";
    size_t numPayloadBytes = strlen(payload) + 1;
    int16_t ttl = 0;
    ret = DPS_Publish(pub, payload, numPayloadBytes, ttl);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Sending a publication] */

Exit:
    return ret;
}

static DPS_Status Publish(DPS_Node* node, DPS_Publication** createdPub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Creating a publication] */
    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Creating a publication] */

    ret = SendPublication(pub);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    *createdPub = pub;
    return ret;
}

static DPS_Status PublishAck(DPS_Node* node, DPS_Publication** createdPub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Requesting an acknowledgement] */
    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL,
                              AcknowledgementHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Requesting an acknowledgement] */

    ret = SendPublication(pub);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    *createdPub = pub;
    return ret;
}

static DPS_Status Subscribe(DPS_Node* node, DPS_Subscription** createdSub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Creating a subscription] */
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    DPS_Subscription* sub = DPS_CreateSubscription(node, topics, numTopics);
    if (!sub) {
        goto Exit;
    }
    /** [Creating a subscription] */

    /** [Subscribing] */
    ret = DPS_Subscribe(sub, PublicationHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Subscribing] */

Exit:
    *createdSub = sub;
    return ret;
}

/** [Receiving a publication] */
static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t numPayloadBytes)
{
    size_t i;

    for (i = 0; i < DPS_SubscriptionGetNumTopics(sub); ++i) {
        const char* topic = DPS_SubscriptionGetTopic(sub, i);
        DPS_PRINT("subscription topic[%ld]=%s\n", i, topic);
    }

    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    DPS_PRINT("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    DPS_PRINT("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        DPS_PRINT("publication topic[%ld]=%s\n", i, topic);
    }

    DPS_PRINT("payload=%s\n", payload);

    /** [Sending an acknowledgement] */
    if (DPS_PublicationIsAckRequested(pub)) {
        const char* payload = "World";
        size_t numPayloadBytes = strlen(payload) + 1;
        DPS_Status ret = DPS_AckPublication(pub, payload, numPayloadBytes);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    /** [Sending an acknowledgement] */

Exit:
    return;
}
/** [Receiving a publication] */

/** [Receiving an acknowledgement] */
static void AcknowledgementHandler(DPS_Publication* pub,
                                   uint8_t* payload, size_t numPayloadBytes)
{
    size_t i;

    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    DPS_PRINT("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    DPS_PRINT("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        DPS_PRINT("publication topic[%ld]=%s\n", i, topic);
    }

    DPS_PRINT("payload=%s\n", payload);
}
/** [Receiving an acknowledgement] */

static void NodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_ERR_OK);
}

static void DestroyNode(DPS_Node* node)
{
    DPS_Status ret;
    DPS_Event* event = DPS_CreateEvent();
    ret = DPS_DestroyNode(node, NodeDestroyed, event);
    if (ret == DPS_OK) {
        DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
}
