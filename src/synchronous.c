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

#include <uv.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/synchronous.h>
#include <dps/event.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static void OnLinked(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, status);
}

static void OnResolve(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Status ret;
    DPS_Event* event = (DPS_Event*)data;

    if (addr) {
        DPS_NodeAddress* outAddr = (DPS_NodeAddress*)DPS_GetEventData(event);
        DPS_CopyAddress(outAddr, addr);
        ret = DPS_OK;
    } else {
        ret = DPS_ERR_UNRESOLVED;
    }
    DPS_SignalEvent(event, ret);
}

DPS_Status DPS_LinkTo(DPS_Node* node, const char* host, uint16_t port, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    char portStr[8];
    DPS_Event* event = DPS_CreateEvent();

    if (!event) {
        return DPS_ERR_RESOURCES;
    }

    sprintf(portStr, "%d", port);

    DPS_SetEventData(event, addr);
    ret = DPS_ResolveAddress(node, host, portStr, OnResolve, event);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_ResolveAddress returned %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = DPS_WaitForEvent(event);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to resolve %s/%d\n", host ? host : "<localhost>", port);
        goto Exit;
    }
    ret = DPS_Link(node, addr, OnLinked, event);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_Link returned: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    ret = DPS_WaitForEvent(event);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to link to %s/%d\n", host ? host : "<localhost>", port);
        goto Exit;
    }

    DPS_DBGPRINT("Resolved address for %s/%d\n", host ? host : "<localhost>", port);

Exit:

    DPS_DestroyEvent(event);
    return ret;
}

static void OnUnlinked(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

DPS_Status DPS_UnlinkFrom(DPS_Node* node, DPS_NodeAddress* addr)
{
    DPS_Status ret;
    DPS_Event* event = DPS_CreateEvent();
    if (!event) {
        return DPS_ERR_RESOURCES;
    }
    ret = DPS_Unlink(node, addr, OnUnlinked, event);
    if (ret == DPS_OK) {
        ret = DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
    return ret;
}
