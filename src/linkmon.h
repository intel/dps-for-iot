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

#ifndef _LINKMON_H
#define _LINKMON_H

#include <stdint.h>
#include <stddef.h>
#include "node.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const LinkMonitorConfig LinkMonitorConfigDefaults;

/*
 * Structure for holding information about a muted remote that is
 * being monitored to detect network disconnects.
 */
typedef struct _LinkMonitor {
    uint8_t retries;       /* Count of failed probes */
    uint8_t probeReceived; /* Was the last probe received */
    DPS_Node* node;        /* The local node */
    DPS_Subscription* sub; /* The mesh monitor subscription */
    DPS_Publication* pub;  /* The mesh monitor publication */
    uv_timer_t timer;      /* The uv timer for this monitor */
    RemoteNode* remote;    /* The muted remote that is being monitored */
} LinkMonitor;

/*
 * Start monitoring a muted link for disconnections.
 *
 * Knowing that we have a loop we periodically send out a publication
 * on the muted connection and start a timer. Link lost is detected if
 * N consective publications are not received within the timeout
 * period and the link is unmuted to restore connectivity over the
 * redundant path. Note that ordinarily publications are not permitted
 * on a muted remote so this is handled as a special case.
 *
 * @param node    The local node
 * @param remote  A remote node that has been muted
 */
DPS_Status DPS_LinkMonitorStart(DPS_Node* node, RemoteNode* remote);

/**
 * Stop monitoring a muted link and free resources.
 */
void DPS_LinkMonitorStop(RemoteNode* remote);


#ifdef __cplusplus
}
#endif

#endif
