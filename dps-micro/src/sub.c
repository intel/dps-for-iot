/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/uuid.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include <dps/private/node.h>
#include <dps/private/bitvec.h>
#include <dps/private/topics.h>
#include <dps/private/sub.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

DPS_Status DPS_InitSubscription(DPS_Node* node, DPS_Subscription* sub, const char* const* topics, size_t numTopics)
{
    DPS_Status ret = DPS_OK;
    size_t i;

    DPS_DBGTRACE();

    if (!node || !sub || !topics) {
        return DPS_ERR_NULL;
    }
    if (numTopics == 0) {
        return DPS_ERR_ARGS;
    }
    if (numTopics > DPS_MAX_SUB_TOPICS) {
        return DPS_ERR_RESOURCES;
    }
    memset(sub, 0, sizeof(DPS_Subscription));

    sub->node = node;
    /*
     * Add the topics to the subscription
     */
    for (i = 0; i < numTopics; ++i) {
        ret = DPS_AddTopic(&sub->bf, topics[i], node->separators, DPS_SubTopic);
        if (ret != DPS_OK) {
            break;
        }
        sub->topics[i] = topics[i];
        ++sub->numTopics;
    }
    return ret;
}

/*
 * Unlink a subscription if it is linked
 */
static int UnlinkSub(DPS_Subscription* sub)
{
    if (sub->node->subscriptions == sub) {
        sub->node->subscriptions = sub->next;
        return DPS_TRUE;
    } else {
        DPS_Subscription* prev = sub->node->subscriptions;
        while (prev && (prev->next != sub)) {
            prev = prev->next;
        }
        if (prev) {
            prev->next = sub->next;
            return DPS_TRUE;
        }
    }
    return DPS_FALSE;
}

DPS_Status DPS_UpdateSubs(DPS_Node* node)
{
    /* TODO - implement this */
    return DPS_OK;
}

DPS_Status DPS_Subscribe(DPS_Subscription* sub, DPS_PublicationHandler handler, void* data)
{
    if (!sub || !handler) {
        return DPS_ERR_NULL;
    }
    if (!sub->handler) {
        sub->next = sub->node->subscriptions;
        sub->node->subscriptions = sub;
        /* This tells the upstream node that subscriptions have changed */
        DPS_UpdateSubs(sub->node);
    }
    sub->handler = handler;
    sub->userData = data;
    return DPS_OK;
}

DPS_Status DPS_DestroySubscription(DPS_Subscription* sub)
{
    DPS_DBGTRACE();

    if (!sub) {
        return DPS_ERR_NULL;
    }
    if (UnlinkSub(sub)) {
        /* This tell the upstream node that subscriptions have changed */
        DPS_UpdateSubs(sub->node);
    }
    memset(sub, 0, sizeof(DPS_Subscription));
    return DPS_OK;
}
