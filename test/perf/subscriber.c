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

#include <assert.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>

static const char* topic = "dps/roundtrip";
static int payloadSize = 0;
static uint8_t* payload = NULL;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    if (DPS_PublicationIsAckRequested(pub)) {
        DPS_Status ret;
        if (payloadSize < 0) {
            ret = DPS_AckPublication(pub, data, len);
        } else {
            ret = DPS_AckPublication(pub, payload, payloadSize);
        }
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
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
    char** arg = argv + 1;
    DPS_Event* nodeDestroyed = NULL;
    DPS_Subscription* subscription = NULL;
    int listenPort = 0;
    DPS_NodeAddress* listenAddr = NULL;
    struct sockaddr_in6 saddr;
    DPS_Node* node;

    DPS_Debug = DPS_FALSE;

    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (IntArg("-s", &arg, &argc, &payloadSize, -1,  UINT16_MAX)) {
            continue;
        }
        if (IntArg("-p", &arg, &argc, &listenPort, 0,  UINT16_MAX)) {
            continue;
        }
        goto Usage;
    }

    node = DPS_CreateNode("/", NULL, NULL);
    nodeDestroyed = DPS_CreateEvent();

    node = DPS_CreateNode("/", NULL, NULL);
    listenAddr = DPS_CreateAddress();
    if (!listenAddr) {
        ret = DPS_ERR_RESOURCES;
        DPS_ERRPRINT("DPS_CreateAddress failed: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
    saddr.sin6_port = htons(listenPort);
    memcpy(&saddr.sin6_addr, &in6addr_any, sizeof(saddr.sin6_addr));
    DPS_SetAddress(listenAddr, (const struct sockaddr*)&saddr);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_RECV, listenAddr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(node));

    if (payloadSize > 0) {
        payload = malloc(payloadSize);
    }
    subscription = DPS_CreateSubscription(node, &topic, 1);
    ret = DPS_Subscribe(subscription, OnPubMatch);

Exit:
    if (ret != DPS_OK) {
        DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroySubscription(subscription);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyAddress(listenAddr);
    return (ret == DPS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;

Usage:
    DPS_PRINT("Usage %s [-d] [-s <size>]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -p: port to listen on.\n");
    DPS_PRINT("       -s: Size of ACK payload.\n");
    return EXIT_FAILURE;
}
