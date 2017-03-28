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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
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

/*
 * Time before sending the first probe
 */
#define FIRST_TO  DPS_SECS_TO_MS(60)

/*
 * Repeat rate for probes
 */
#define PROBE_TO  DPS_SECS_TO_MS(120)

/*
 * Timer for retries following a probe failure
 */
#define RETRY_TO  DPS_SECS_TO_MS(5)

/*
 * Maximum number of retries following a probe failure
 */
#define MAX_PROBE_RETRIES  3


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
    if (monitor->pub) {
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

void DPS_LinkMonitorStop(RemoteNode* remote)
{
    if (remote->monitor) {
        DestroyLinkMonitor(remote->monitor);
    }
}

static void OnProbeTimeout(uv_timer_t* handle)
{
    DPS_Status ret = DPS_ERR_TIMEOUT;
    LinkMonitor* monitor = (LinkMonitor*)handle->data;

    if (monitor->probeReceived) {
        monitor->probeReceived = DPS_FALSE;
        /*
         * If in retry mode restore timer back to normal
         */
        if (monitor->retries != 0) {
            DPS_DBGPRINT("Link probe recover after retry %d\n", monitor->retries);
            uv_timer_set_repeat(handle, PROBE_TO);
            monitor->retries = 0;
        }
        ret = DPS_OK;
    } else if (monitor->retries < MAX_PROBE_RETRIES) {
        /*
         * Set shorter timeout for retries
         */
        if (monitor->retries++ == 0) {
            uv_timer_set_repeat(handle, RETRY_TO);
        }
        DPS_DBGPRINT("Link probe failed retry %d\n", monitor->retries);
        ret = DPS_OK;
    }
    /*
     * Send a next probe
     */
    if (ret == DPS_OK) {
        /*
         * We need to send the publication directly to the muted remote
         */
        ret = DPS_Publish(monitor->pub, NULL, 0, 0);
        if (ret == DPS_OK) {
            DPS_DBGPRINT("Send link probe to %s\n", DESCRIBE(monitor->remote));
            ret = DPS_SendPublication(monitor->node, monitor->pub, monitor->pub->bf, monitor->remote);
            /*
             * We have to delete the publication history for the probe otherwise
             * it will look like a duplicate and will be discarded.
             */
            DPS_DeletePubHistory(&monitor->node->history, &monitor->pub->pubId);
        }
    }

    if (ret != DPS_OK) {
        DPS_DBGPRINT("Link probe failed on retry %d\n", monitor->retries);
        DPS_UnmuteRemoteNode(monitor->node, monitor->remote);
    }
}

DPS_Status DPS_LinkMonitorStart(DPS_Node* node, RemoteNode* remote)
{
    DPS_Status ret;
    LinkMonitor* monitor = NULL;
    char topic[25];
    const char* topics[1];

    assert(remote->muted);
    assert(!remote->monitor);
    assert(!remote->linked);

    /*
     * Create a random topic string for the probe publication
     */
    snprintf(topic, sizeof(topic), "%x%x%x", DPS_Rand(), DPS_Rand(), DPS_Rand());
    topics[0] = topic;

    monitor = calloc(1, sizeof(LinkMonitor));
    if (!monitor) {
        ret = DPS_ERR_RESOURCES;
        goto ErrorExit;
    }
    monitor->probeReceived = DPS_TRUE;
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
     * Create and start the mesh monitor timer
     */
    if (uv_timer_init(node->loop, &monitor->timer)) {
        ret = DPS_ERR_FAILURE;
        goto ErrorExit;
    }
    monitor->timer.data = monitor;
    if (uv_timer_start(&monitor->timer, OnProbeTimeout, FIRST_TO, PROBE_TO)) {
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
