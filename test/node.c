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

#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include "keys.h"

#define MAX_TOPICS 64
#define MAX_RECIPIENTS 8
#define MAX_LINKS  8

static DPS_Event* event = NULL;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

static void TimedWait(uint16_t msecs)
{
    DPS_TimedWaitForEvent(event, msecs);
}

static void Wait()
{
    DPS_WaitForEvent(event);
}

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t numTopics;
    size_t i;
    DPS_Status ret;

    DPS_PRINT("Pub %s(%d)\n", DPS_UUIDToString(pubId), sn);
    DPS_PRINT("  pub ");
    numTopics = DPS_PublicationGetNumTopics(pub);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" | ");
        }
        DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
    }
    DPS_PRINT("\n");

    if (DPS_PublicationIsAckRequested(pub)) {
        ret = DPS_AckPublication(pub, NULL, 0);
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void AcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);

    DPS_PRINT("Ack %s(%d)\n", DPS_UUIDToString(pubId), sn);
}

static int SameId(const DPS_KeyId* keyId, const char* idStr)
{
    return keyId && idStr && (strlen(idStr) == keyId->len) && !memcmp(idStr, keyId->id, keyId->len);
}

static const Id* LookupId(const char* idStr)
{
    const Id* id;

    for (id = Ids; id->keyId.id; ++id) {
        if (SameId(&id->keyId, idStr)) {
            return id;
        }
    }
    return NULL;
}

static DPS_MemoryKeyStore* CreateKeyStore(const Id* self)
{
    DPS_MemoryKeyStore* keyStore;
    const Id* id;

    keyStore = DPS_CreateMemoryKeyStore();
    DPS_SetTrustedCA(keyStore, TrustedCAs);
    for (id = Ids; id->keyId.id; ++id) {
        if (id == self) {
            DPS_SetCertificate(keyStore, id->cert, id->privateKey, id->password);
        } else {
            DPS_SetCertificate(keyStore, id->cert, NULL, NULL);
        }
    }
    return keyStore;
}

static void DumpId(const DPS_KeyId* id)
{
    size_t i;

    if (id) {
        for (i = 0; i < id->len; ++i) {
            DPS_PRINT("%02x ", id->id[i]);
        }
        DPS_PRINT("\n");
    } else {
        DPS_PRINT("<null>\n");
    }
}

static void LogPermissionHandler(DPS_PermissionStoreRequest* request, int authorized)
{
    const DPS_KeyId* id;
    const DPS_KeyId* endId = DPS_GetEndToEndId(request);

    id = DPS_GetEndToEndId(request);
    if (id) {
        DPS_PRINT("%.*s/", id->len, id->id);
    } else {
        DPS_PRINT("<null>/");
    }
    id = DPS_GetNetworkId(request);
    if (id) {
        DPS_PRINT("%.*s ", id->len, id->id);
    } else {
        DPS_PRINT("<null> ");
    }
    switch (DPS_GetPermission(request)) {
    case DPS_PERM_PUB: DPS_PRINT("PUB "); break;
    case DPS_PERM_SUB: DPS_PRINT("SUB "); break;
    case DPS_PERM_ACK: DPS_PRINT("ACK "); break;
    default: break;
    }
    DPS_PRINT("%s\n", authorized ? "Authorized": "Denied");
}

static int PermissionHandler(DPS_PermissionStoreRequest* request)
{
    const char *T = "T";
    int ret = DPS_FALSE;

    if (SameId(DPS_GetEndToEndId(request), "alice") &&
        (DPS_GetPermission(request) & DPS_PERM_PUB) &&
        (DPS_IncludesTopics(request, &T, 1) == DPS_OK)) {
        ret = DPS_TRUE;
    } else if (SameId(DPS_GetEndToEndId(request), "bob") &&
               (DPS_GetPermission(request) & DPS_PERM_ACK) &&
               (DPS_IncludesTopics(request, &T, 1) != DPS_ERR_FAILURE)) {
        ret = DPS_TRUE;
    }
    /*
     * Network ID only available with DTLS transport.
     */
#if defined(DPS_USE_DTLS)
    if (SameId(DPS_GetNetworkId(request), "bob") &&
        (DPS_GetPermission(request) & DPS_PERM_SUB) &&
        (DPS_IncludesTopics(request, &T, 1) == DPS_OK)) {
        ret = DPS_TRUE;
    } else if (SameId(DPS_GetNetworkId(request), "trudy") &&
               (DPS_GetPermission(request) & DPS_PERM_SUB) &&
               (DPS_IncludesTopics(request, &T, 1) == DPS_OK)) {
        ret = DPS_TRUE;
    } else if (SameId(DPS_GetNetworkId(request), "trent")) {
        ret = DPS_TRUE;
    }
#else
    if ((DPS_GetPermission(request) & DPS_PERM_SUB) &&
        (DPS_IncludesTopics(request, &T, 1) == DPS_OK)) {
        ret = DPS_TRUE;
    }
#endif

    LogPermissionHandler(request, ret);
    return ret;
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
    char** arg = argv + 1;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    int useMemoryPermissionStore = DPS_FALSE;
    const char* user;
    char* subs[MAX_TOPICS];
    size_t numSubs = 0;
    char* pubs[MAX_TOPICS];
    size_t numPubs = 0;
    char* recipients[MAX_RECIPIENTS];
    size_t numRecipients = 0;
    DPS_AcknowledgementHandler ackHandler = AcknowledgementHandler;
    int links[MAX_LINKS];
    size_t numLinks = 0;
    int listenPort = 0;

    DPS_Node* node = NULL;
    const Id* self = NULL;
    DPS_NodeAddress* addr = NULL;
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_PermissionStore* permStore = NULL;
    DPS_MemoryPermissionStore* memoryPermStore = NULL;
    DPS_Subscription* subscription = NULL;
    DPS_Publication* publication = NULL;
    const Id* id;
    DPS_Status ret = DPS_OK;
    size_t i;

    DPS_Debug = 0;

    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
        } else if (strcmp(*arg, "-m") == 0) {
            ++arg;
            useMemoryPermissionStore = DPS_TRUE;
        } else if (strcmp(*arg, "-u") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            user = *arg++;
        } else if (strcmp(*arg, "-s") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            subs[numSubs++] = *arg++;
        } else if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            pubs[numPubs++] = *arg++;
        } else if (strcmp(*arg, "-r") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            recipients[numRecipients++] = *arg++;
        } else if (IntArg("-c", &arg, &argc, &links[numLinks], 1, UINT16_MAX)) {
            ++numLinks;
        } else if (IntArg("-l", &arg, &argc, &listenPort, 1000, UINT16_MAX)) {
        } else {
            goto Usage;
        }
    }
    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (numLinks) {
        mcast = DPS_MCAST_PUB_DISABLED;
        addr = DPS_CreateAddress();
    }

    event = DPS_CreateEvent();
    if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }

    self = LookupId(user);
    if (!self) {
        ret = DPS_ERR_ARGS;
        goto Usage;
    }
    keyStore = CreateKeyStore(self);
    if (!keyStore) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    if (useMemoryPermissionStore) {
        const char *T = "T";
        memoryPermStore = DPS_CreateMemoryPermissionStore();
        DPS_SetPermission(memoryPermStore, &T, 1, &LookupId("alice")->keyId, DPS_PERM_PUB);
        DPS_SetPermission(memoryPermStore, &T, 1, &LookupId("bob")->keyId, DPS_PERM_SUB | DPS_PERM_ACK);
        DPS_SetPermission(memoryPermStore, &T, 1, &LookupId("trudy")->keyId, DPS_PERM_SUB);
        DPS_SetPermission(memoryPermStore, NULL, 0, &LookupId("trent")->keyId,
                          DPS_PERM_PUB | DPS_PERM_SUB | DPS_PERM_ACK | DPS_PERM_FORWARD);
        /*
         * Network ID only available with DTLS transport.
         */
#if !defined(DPS_USE_DTLS)
        DPS_SetPermission(memoryPermStore, NULL, 0, NULL, DPS_PERM_SUB);
#endif
        permStore = DPS_MemoryPermissionStoreHandle(memoryPermStore);
    } else {
        permStore = DPS_CreatePermissionStore(PermissionHandler);
        if (!permStore) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
    }

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), &self->keyId);
    if (!node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_SetPermissionStore(node, permStore);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_StartNode(node, mcast, listenPort);
    if (ret != DPS_OK) {
        goto Exit;
    }

    if (numSubs) {
        subscription = DPS_CreateSubscription(node, (const char**)subs, numSubs);
        if (!subscription) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_Subscribe(subscription, PublicationHandler);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }

    if (numPubs) {
        publication = DPS_CreatePublication(node);
        if (!publication) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_InitPublication(publication, (const char**)pubs, numPubs, DPS_FALSE, NULL, ackHandler);
        if (ret != DPS_OK) {
            goto Exit;
        }
        for (i = 0; i < numRecipients; ++i) {
            id = LookupId(recipients[i]);
            if (!id) {
                ret = DPS_ERR_ARGS;
                goto Exit;
            }
            ret = DPS_PublicationAddKeyId(publication, &id->keyId);
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
    }

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node, NULL, links[i], addr);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    if (numLinks) {
        /* Wait for links to settle */
        TimedWait(500);
    }

    if (publication) {
        ret = DPS_Publish(publication, NULL, 0, 0);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }

    Wait();

Exit:
    if (publication) {
        DPS_DestroyPublication(publication);
    }
    if (subscription) {
        DPS_DestroySubscription(subscription);
    }
    if (node) {
        ret = DPS_DestroyNode(node, OnNodeDestroyed, event);
        if (ret == DPS_OK) {
            DPS_WaitForEvent(event);
        }
    }
    if (memoryPermStore) {
        DPS_DestroyMemoryPermissionStore(memoryPermStore);
    } else if (permStore) {
        DPS_DestroyPermissionStore(permStore);
    }
    if (keyStore) {
        DPS_DestroyMemoryKeyStore(keyStore);
    }
    if (event) {
        DPS_DestroyEvent(event);
    }
    if (addr) {
        DPS_DestroyAddress(addr);
    }
    return ret;

Usage:
    DPS_PRINT("Usage %s [-d] [-m] [-u <user>] [-s <topic>] [-p <topic>] [-l <portnum>] [-c <portnum>]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -m: Use in-memory permission store.\n");
    DPS_PRINT("       -u: Set user ID.\n");
    DPS_PRINT("       -s: Subscribe to topic.  May be repeated.\n");
    DPS_PRINT("       -p: Publish to topic.  May be repeated.\n");
    DPS_PRINT("       -r: Recipient of publication.  May be repeated.\n");
    DPS_PRINT("       -l: Port number to listen on for incoming connections.\n");
    DPS_PRINT("       -c: Port to link to.  May be repeated.\n");
    return DPS_ERR_FAILURE;
}
