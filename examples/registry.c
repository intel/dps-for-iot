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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/registration.h>
#include <dps/event.h>

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_AckPublication(pub, NULL, 0);
    if (ret != DPS_OK) {
        DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
    }
}

static int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return 0;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    char** arg = ++argv;
    DPS_Node* node;
    DPS_Event* nodeDestroyed;
    const char* topics[1];
    DPS_Subscription* subscription;
    int listenPort = 30000;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
    }

    node = DPS_CreateNode("/", NULL, NULL, 0);
    ret = DPS_StartNode(node, 0, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Registration services is listening on port %d\n", DPS_GetPortNumber(node));

    nodeDestroyed = DPS_CreateEvent();

    topics[0] = DPS_RegistryTopicString;
    subscription = DPS_CreateSubscription(node, topics, 1);
    ret = DPS_Subscribe(subscription, OnPubMatch);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
        DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-l <listen port] [-d]\n", *argv);
    return 1;
}
