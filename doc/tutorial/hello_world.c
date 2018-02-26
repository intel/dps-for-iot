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
#include <dps/dps.h>
/** [Prerequisites] */

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
    printf("Usage %s [-d] [publish|subscribe] [ack]\n", argv[0]);
    printf("       -d: Enable debug ouput if built for debug.\n");
}

int main(int argc, char** argv)
{
    DPS_Publication* pub = NULL;
    DPS_Subscription* sub = NULL;
    int publish = DPS_FALSE;
    int subscribe = DPS_FALSE;
    int ack = DPS_FALSE;
    int i;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "publish")) {
            publish = DPS_TRUE;
        } else if (!strcmp(argv[i], "subscribe")) {
            subscribe = DPS_TRUE;
        } else if (!strcmp(argv[i], "ack")) {
            ack = DPS_TRUE;
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

    /** [Starting a node] */
    int mcastPub = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    int listenPort = 0;
    DPS_Status ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Starting a node] */

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

    /* Sleep until user enters EOF */
    fgetc(stdin);

Exit:
    DPS_DestroyPublication(pub);
    DPS_DestroySubscription(sub);
    DestroyNode(node);
    return EXIT_SUCCESS;
}

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
        printf("subscription topic[%ld]=%s\n", i, topic);
    }

    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    printf("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    printf("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        printf("publication topic[%ld]=%s\n", i, topic);
    }

    printf("payload=%s\n", payload);

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
    printf("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    printf("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        printf("publication topic[%ld]=%s\n", i, topic);
    }

    printf("payload=%s\n", payload);
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

/**
 * @page hello-world Hello world
 * @tableofcontents
 *
 * @section prerequisites Prerequisites
 * @snippet this Prerequisites
 *
 * The first step in creating a DPS application is to include the
 * necessary header files.
 *
 * @section creating-a-node Creating a node
 * @snippet this Creating a node
 *
 * Each entity in DPS is represented by a @c DPS_Node.  The node may
 * be a publisher, subscriber, both, or neither.  For this example,
 * we're going to be creating publisher and subscriber nodes.
 *
 * Creating a node requires three parameters: the topic separators, a
 * key store, and a key identifier.  For now we're only concerned with
 * the separators.  Key stores and identifiers are covered later when
 * discussing how to secure communications.
 *
 * The separators parameter is a string containing the characters used
 * as topic level separators.  A topic is composed of multiple levels
 * with separators between them.  Providing @c /. as the separators
 * parameter value means all of the following topics are equivalent:
 * @code
 * a/b/c/d
 * a.b.c.d
 * a/b.c/d
 * @endcode
 *
 * @see DPS_SetNodeData(), DPS_GetNodeData()
 *
 * @section starting-a-node Starting a node
 * @snippet this Starting a node
 *
 * Once created, a node must be started.  Starting a node enables it
 * to begin sending and receiving DPS messages in the network.
 *
 * For this example, we are going to be sending and receiving
 * multicast publications so we enable both and let DPS assign the
 * listening port.
 *
 * @see DPS_MCAST_PUB_DISABLED, DPS_GetPortNumber()
 *
 * @section publishing Publishing
 *
 * @subsection creating-a-publication Creating a publication
 * @snippet this Creating a publication
 *
 * Each publication in DPS is represented by a @c DPS_Publication.
 * Each publication has a set of topics, a UUID, and a sequence
 * number.  In this example we are creating a publication with one
 * topic, @c a/b/c/d.  The UUID is assigned by DPS and the sequence
 * number will be incremented each time we publish.
 *
 * The @c noWildCard parameter is used by the publisher to control
 * whether a subscription is required to match the publication's
 * topics exactly or can use wildcards to match the topics.  If we set
 * @c noWildCard to @c DPS_TRUE then only a subscription to @c a/b/c/d
 * will receive this publication.  Since we set @c noWildCard to @c
 * DPS_FALSE here, subscriptions to @c a/#, @c a/+/+/d, or similar
 * variations will receive this publication.
 *
 * Both the publication's key identifier and acknowledgement handler
 * are set to @c NULL here; they are covered in later sections.
 *
 * @see DPS_SetPublicationData(), DPS_GetPublicationData(),
 *      DPS_PublicationGetNode(), DPS_PublicationGetUUID(),
 *      DPS_PublicationGetSequenceNum()
 *
 * @subsection sending-a-publication Sending a publication
 * @snippet this Sending a publication
 *
 * Once created and initialized with a set of topics, application
 * payloads may be sent.  Payload data is simply an array of bytes in
 * DPS, no assumptions are made with regards to the payload format.
 *
 * In this example the @c ttl parameter is zero, indicating that the
 * publication will be sent best-effort to all active subscribing
 * nodes.  A non-zero ttl is referred to as a retained publication
 * and is covered later.
 *
 * Recall also that a publisher may send application data multiple
 * times, and each send increments the sequence number of the
 * publication.
 *
 * @section subscribing Subscribing
 *
 * @subsection creating-a-subscription Creating a subscription
 * @snippet this Creating a subscription
 *
 * Each subscription in DPS is represented by a @c DPS_Subscription.
 * In this example we are creating a subscription with one topic with
 * no wildcards, @c a/b/c/d.
 *
 * Wildcards may be used to match a broader set of topics.  A @c +
 * matches any single topic level, and a @c # matches all topic levels
 * from that level on.  In this instance since the publisher is allowing
 * wildcard matching, the subscriber could use either @c a/b/+/d or @c
 * a/# (among others) as the topic and still receive the publication.
 *
 * A subscription may also be created with multiple topics.  The
 * publication must include @em all of the topics to be received.
 *
 * @see DPS_SetSubscriptionData(), DPS_GetSubscriptionData(),
 *      DPS_SubscriptionGetNode()
 *
 * @subsection receiving-a-publication Receiving a publication
 * @snippet this Subscribing
 *
 * Publications are received asynchronously.  The first step in
 * receiving a publication is to provide the publication handler to
 * DPS and start the subscription.  The publication handler will be
 * called for each received publication.
 *
 * @note Each instance of @c DPS_Node runs in its own thread.  The
 * publication handler is dispatched from this thread.
 *
 * @snippet this Receiving a publication
 *
 * This publication handler exercises the APIs for retrieving the
 * subscription and publication information.
 *
 * @section acknowledging Acknowledging
 *
 * Acknowledgements provide a means for subscribers to reply to
 * publications.  Similar to publications, acknowledgements may
 * include an application payload, and no assumptions are made by DPS
 * with regards to the acknowledgement payload format.
 *
 * @subsection requesting-an-acknowledgement Requesting an acknowledgement
 * @snippet this Requesting an acknowledgement
 *
 * Requesting an acknowledgement is identical to @ref creating-a-publication,
 * with the addition of the @c DPS_AcknowledgementHandler.
 *
 * @subsection sending-an-acknowledgement Sending an acknowledgement
 * @snippet this Sending an acknowledgement
 *
 * To determine if a publication has requested an ack, call
 * DPS_PublicationIsAckRequested().  To send an acknowledgement, along
 * with any optional acknowledgement payload, call
 * DPS_AckPublication().
 *
 * The @c pub parameter of the publication handler is only valid
 * during the body of the handler.  In order to acknowledge a
 * publication after the handler has returned, the application must
 * first call DPS_CopyPublication() to create a partial copy of the
 * publication.  The copy may be used after the handler returns.
 *
 * @subsection receiving-an-acknowledgement Receiving an acknowledgement
 * @snippet this Receiving an acknowledgement
 *
 * Acknowledgements are received asynchronously.  The acknowledgement
 * handler will be called for each received acknowledgement.
 *
 * This acknowledgement handler exercises the APIs for retrieving the
 * publication information associated with the acknowledgement.
 *
 * @note The acknowledgement handler is dispatched from the @c
 * DPS_Node's thread.
 */
