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

#ifndef _DPS_SYNCHRONOUS_H
#define _DPS_SYNCHRONOUS_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup node
 * @{
 */

/**
 * Synchronous helper that wraps DPS_Link().
 *
 * @param node  The local node to link from
 * @param host  The host name or IP address to link to
 * @param port  The port number
 * @param addr  Returns the resolved address for the remote node
 *
 */
DPS_Status DPS_LinkTo(DPS_Node* node, const char* host, uint16_t port, DPS_NodeAddress* addr);

/**
 * Synchronous helper that wraps DPS_Unlink().
 *
 * @param node  The local node to unlink from
 * @param addr  The address of the remote node to unlink
 */
DPS_Status DPS_UnlinkFrom(DPS_Node* node, DPS_NodeAddress* addr);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
