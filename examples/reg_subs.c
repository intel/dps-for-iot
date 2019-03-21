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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/registration.h>
#include <dps/synchronous.h>
#include "common.h"
#include "keys.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

static int quiet = DPS_FALSE;

static uint8_t AckMsg[] = "This is an ACK";

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    const DPS_KeyId* senderId = DPS_PublicationGetSenderKeyId(pub);
    size_t i;
    size_t numTopics = DPS_SubscriptionGetNumTopics(sub);

    if (!quiet) {
        DPS_PRINT("Pub %s(%d) [%s] matches:\n", DPS_UUIDToString(pubId), sn, KeyIdToString(senderId));
        DPS_PRINT("  pub ");
        numTopics = DPS_PublicationGetNumTopics(pub);
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" | ");
            }
            DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
        }
        DPS_PRINT("\n");
        DPS_PRINT("  sub ");
        numTopics = DPS_SubscriptionGetNumTopics(sub);
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" & ");
            }
            DPS_PRINT("%s", DPS_SubscriptionGetTopic(sub, i));
        }
        DPS_PRINT("\n");
        if (data) {
            DPS_PRINT("%.*s\n", (int)len, data);
        }
    }
    if (DPS_PublicationIsAckRequested(pub)) {
        DPS_Status ret = DPS_AckPublication(pub, AckMsg, sizeof(AckMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

static DPS_Status RegisterAndJoin(DPS_Node* node, char** linkText, int numLink,
                                  const char* tenant, uint8_t count, uint16_t timeout)
{
    DPS_Status ret = DPS_OK;
    DPS_RegistrationList* regs = NULL;
    DPS_NodeAddress* remoteAddr = NULL;
    int i;

    for (i = 0; i < numLink; ++i) {
        /*
         * Register with the registration service
         */
        regs = DPS_CreateRegistrationList(count);
        ret = DPS_Registration_PutSyn(node, linkText[i], tenant, DPS_REGISTRATION_PUT_TIMEOUT);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to register with registration service: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
        /*
         * Find nodes to join
         */
        ret = DPS_Registration_GetSyn(node, linkText[i], tenant, regs, timeout);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Registration service lookup failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
        DPS_PRINT("Found %d remote nodes\n", regs->count);

        if (regs->count == 0) {
            return DPS_ERR_NO_ROUTE;
        }
        for (i = 0; i < regs->count; ++i) {
            DPS_PRINT("  %s\n", regs->list[i].addrText);
        }
        remoteAddr = DPS_CreateAddress();
        ret = DPS_Registration_LinkToSyn(node, regs, remoteAddr);
        if (ret == DPS_OK) {
            char* str = NULL;
            /*
             * DPS_NodeAddrToString uses a static buffer, so dup one of
             * the strs used below.
             */
            str = strdup(DPS_GetListenAddressString(node));
            DPS_PRINT("%s is linked to %s\n", str, DPS_NodeAddrToString(remoteAddr));
            if (str) {
                free(str);
            }
        }
        DPS_DestroyAddress(remoteAddr);
        DPS_DestroyRegistrationList(regs);
    }
    return ret;
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_Event* nodeDestroyed;
    char* topics[64];
    char** arg = ++argv;
    const char* tenant = "anonymous_tenant";
    size_t numTopics = 0;
    DPS_MemoryKeyStore* memoryKeyStore = NULL;
    DPS_Node* node;
    DPS_NodeAddress* listenAddr = NULL;
    int subsRate = DPS_SUBSCRIPTION_UPDATE_RATE;
    int timeout = DPS_REGISTRATION_GET_TIMEOUT;
    int count = 16;
    DPS_NodeAddress* linkAddr[MAX_LINKS] = { NULL };
    char* linkText[MAX_LINKS] = { NULL };
    int numLinks = 0;

    DPS_Debug = DPS_FALSE;

    while (--argc) {
        if (ListenArg(&arg, &argc, &listenAddr)) {
            continue;
        }
        if (LinkArg(&arg, &argc, linkText, &numLinks)) {
            continue;
        }
        if (IntArg("-r", &arg, &argc, &subsRate, 0, INT32_MAX)) {
            continue;
        }
        if (IntArg("--timeout", &arg, &argc, &timeout, 0, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-c", &arg, &argc, &count, 1, UINT8_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-t") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            tenant = *arg++;
            continue;
        }
        if (strcmp(*arg, "-q") == 0) {
            ++arg;
            quiet = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topics)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }

    if (!numLinks) {
        DPS_PRINT("Need link address\n");
        goto Usage;
    }

    memoryKeyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(memoryKeyStore, &NetworkKeyId, &NetworkKey);
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(memoryKeyStore), NULL);
    DPS_SetNodeSubscriptionUpdateDelay(node, subsRate);

    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, listenAddr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Subscriber is listening on %s\n", DPS_GetListenAddressString(node));

    nodeDestroyed = DPS_CreateEvent();

    ret = RegisterAndJoin(node, linkText, numLinks, tenant, count, timeout);
    if (ret != DPS_OK) {
        DPS_PRINT("Failed to link with any other \"%s\" nodes - continuing\n", tenant);
    }

    if (numTopics > 0) {
        DPS_Subscription* subscription = DPS_CreateSubscription(node, (const char**)topics, numTopics);
        ret = DPS_Subscribe(subscription, OnPubMatch);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
        }
    }

    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(memoryKeyStore);
    DPS_DestroyAddress(listenAddr);
    DestroyLinkArg(linkText, linkAddr, numLinks);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-l <address>] [-p <address>] [-t <tenant string>] [-r <milliseconds>] [-c <count>] [--timeout <milliseconds>] topic1 topic2 ... topicN\n", *argv);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -l: Address to listen on.\n");
    DPS_PRINT("       -p: Address to link.\n");
    DPS_PRINT("       -t: Tenant string to use.\n");
    DPS_PRINT("       -r: Time to delay between subscription updates.\n");
    DPS_PRINT("       -c: Size of registration get request.\n");
    DPS_PRINT("       --timeout: Timeout of registration get request.\n");
    return 1;
}
