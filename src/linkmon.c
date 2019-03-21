/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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
#include <ctype.h>
#include <safe_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include "node.h"
#include "pub.h"
#include "sub.h"
#include "linkmon.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define DESCRIBE(n)  DPS_NodeAddrToString(&(n)->ep.addr)

const LinkMonitorConfig LinkMonitorConfigDefaults = {
    .retries = 3,      /* Maximum number of retries following a probe failure */
    .probeTO = 120000, /* Base repeat rate for probes */
    .retryTO = 200     /* Repeat time for retries following a probe failure */
};

static void ProbePubHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    LinkMonitor* monitor = DPS_GetSubscriptionData(sub);

    if (monitor) {
        DPS_DBGPRINT("Link probe received\n");
        monitor->probeReceived = DPS_TRUE;
    }
}

static void OnTimerClosed(uv_handle_t* handle)
{
    free(handle->data);
}

static void DestroyLinkMonitor(LinkMonitor* monitor)
{
    DPS_DBGTRACE();
    if (monitor->pub) {
        DPS_DestroyPublication(monitor->pub);
    }
    if (monitor->sub) {
        DPS_DestroySubscription(monitor->sub);
    }
    /*
     * Unlink from remote
     */
    if (monitor->remote) {
        assert(monitor->remote->monitor == monitor);
        monitor->remote->monitor = NULL;
    }
    if (monitor->timer.data == monitor) {
        uv_timer_stop(&monitor->timer);
        uv_close((uv_handle_t*)&monitor->timer, OnTimerClosed);
    } else {
        free(monitor);
    }
}

static DPS_Status LinkMonitorInit(DPS_Node* node, LinkMonitor* monitor)
{
    DPS_Status ret;
    char topic[25];
    const char* topics[1];

    /*
     * Create a random topic string for the probe publication
     */
    snprintf(topic, sizeof(topic), "%x%x%x", DPS_Rand(), DPS_Rand(), DPS_Rand());
    topics[0] = topic;

    monitor->pub = DPS_CreatePublication(node);
    if (!monitor->pub) {
        ret = DPS_ERR_RESOURCES;
        goto ErrorExit;
    }
    /*
     * Initialize the publication - wildcard matching is not required.
     */
    ret = DPS_InitPublication(monitor->pub, topics, A_SIZEOF(topics), DPS_TRUE, NULL, NULL);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Subscribe to this publication
     */
    monitor->sub = DPS_CreateSubscription(node, topics, A_SIZEOF(topics));
    if (!monitor->sub) {
        ret = DPS_ERR_RESOURCES;
        goto ErrorExit;
    }
    ret = DPS_Subscribe(monitor->sub, ProbePubHandler);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * To access monitor in the ProbePubHandler callback
     */
    DPS_SetSubscriptionData(monitor->sub, monitor);
    /*
     * Assume we start out ok
     */
    monitor->probeReceived = DPS_TRUE;
    return DPS_OK;

ErrorExit:

    DPS_ERRPRINT("Failed to initialize link monitor %s\n", DPS_ErrTxt(ret));
    return ret;
}

void DPS_LinkMonitorStop(RemoteNode* remote)
{
    if (remote->monitor) {
        DPS_DBGPRINT("Node %s no longer monitoring %s\n", remote->monitor->node->addrStr,
                     DESCRIBE(remote));
        DestroyLinkMonitor(remote->monitor);
    }
}

static void OnProbeTimeout(uv_timer_t* handle)
{
    DPS_Status ret = DPS_ERR_TIMEOUT;
    LinkMonitor* monitor = (LinkMonitor*)handle->data;
    DPS_PublishRequest* req = NULL;

    DPS_DBGTRACE();

    if (monitor->node->state != DPS_NODE_RUNNING) {
        return;
    }
    DPS_LockNode(monitor->node);

    if (monitor->probeReceived) {
        monitor->probeReceived = DPS_FALSE;
        /*
         * If in retry mode restore timer back to normal
         */
        if (monitor->retries != 0) {
            DPS_DBGPRINT("Link probe recover after retry %d\n", monitor->retries);
            uv_timer_set_repeat(handle, monitor->node->linkMonitorConfig.probeTO);
            monitor->retries = 0;
        }
        ret = DPS_OK;
    } else if (monitor->retries < monitor->node->linkMonitorConfig.retries) {
        /*
         * Set shorter timeout for retries
         */
        if (monitor->retries++ == 0) {
            uv_timer_set_repeat(handle, monitor->node->linkMonitorConfig.retryTO);
        }
        DPS_DBGPRINT("Link probe failed retry %d\n", monitor->retries);
        ret = DPS_OK;
    }
    /*
     * Send a next probe
     */
    if (ret == DPS_OK) {
        req = DPS_CreatePublishRequest(monitor->pub, 0, NULL, NULL);
        if (!req) {
            ret = DPS_ERR_RESOURCES;
        }
    }
    if (ret == DPS_OK) {
        /*
         * Publications are not normally sent to muted noded so we have
         * to call the lower layer APIs for force the probe publication
         * to be sent.
         */
        req->sequenceNum = ++monitor->pub->sequenceNum;
        ret = DPS_SerializePub(req, NULL, 0, 0);
    }
    if (ret == DPS_OK) {
        DPS_DBGPRINT("Send link probe from %s to %s\n", monitor->node->addrStr,
                     DESCRIBE(monitor->remote));
        ret = DPS_SendPublication(req, monitor->pub, monitor->remote);
        /*
         * We have to delete the publication history for the probe otherwise
         * it will look like a duplicate and will be discarded.
         */
        DPS_DeletePubHistory(&monitor->node->history, &monitor->pub->pubId);
    }
    if (ret != DPS_OK) {
        DPS_DBGPRINT("Link probe failed on retry %d\n", monitor->retries);
        DPS_UnmuteRemoteNode(monitor->node, monitor->remote);
    }

    if (ret == DPS_OK) {
        DPS_PublishCompletion(req);
    } else {
        DPS_DestroyPublishRequest(req);
    }

    DPS_UnlockNode(monitor->node);
}

DPS_Status DPS_LinkMonitorStart(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    LinkMonitor* monitor = NULL;

    assert(remote->outbound.muted && remote->inbound.muted);

    /*
     * We only monitor a muted link from the passive side
     *
     * TODO - the linked flags may not be reliable - we
     * need a different tie breaker if possible.
     */
    if (remote->linked) {
        return DPS_OK;
    }
    assert(!remote->monitor);

    DPS_DBGPRINT("Node %s is monitoring %s\n", node->addrStr, DESCRIBE(remote));

    monitor = calloc(1, sizeof(LinkMonitor));
    if (!monitor) {
        ret = DPS_ERR_RESOURCES;
        goto ErrorExit;
    }
    ret = LinkMonitorInit(node, monitor);
    if (ret != DPS_OK) {
        goto ErrorExit;
    }
    /*
     * Create and start the mesh monitor timer
     */
    if (uv_timer_init(node->loop, &monitor->timer)) {
        ret = DPS_ERR_FAILURE;
        goto ErrorExit;
    }
    monitor->timer.data = monitor;
    if (uv_timer_start(&monitor->timer, OnProbeTimeout, node->linkMonitorConfig.probeTO, node->linkMonitorConfig.probeTO)) {
        ret = DPS_ERR_FAILURE;
        goto ErrorExit;
    }
    /*
     * Cross link the remote and the monitor
     */
    remote->monitor = monitor;
    monitor->remote = remote;
    monitor->node = node;

    return DPS_OK;

ErrorExit:

    DPS_ERRPRINT("Failed to start link monitor %s\n", DPS_ErrTxt(ret));
    if (monitor) {
        DestroyLinkMonitor(monitor);
    }
    return ret;
}
