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

#include "test.h"
#include "keys.h"

#define MAX_TOPICS 64
#define MAX_RECIPIENTS 8

typedef struct _AccessControlEntry {
    const char *topic;
    const char* id;
    enum {
        PUB = (1<<0),
        SUB = (1<<1),
        ACK = (1<<2)
    } bits;
} AccessControlEntry;

static const AccessControlEntry acl[] = {
    { "T", "alice", PUB       },
    { "T", "bob",   SUB | ACK },
    { "T", "trudy", SUB       },
    { NULL, NULL,   0         }
};

static DPS_Event* event = NULL;

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

static int IsAllowed(const DPS_KeyId* keyId, int bits, const DPS_Publication* pub)
{
    const AccessControlEntry* ace;
    size_t i;

    for (ace = acl; ace->id; ++ace) {
        if (SameId(keyId, ace->id) && (bits & ace->bits)) {
            for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
                if (!strcmp(ace->topic, DPS_PublicationGetTopic(pub, i))) {
                    return DPS_TRUE;
                }
            }
        }
    }
    return DPS_FALSE;
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

static void TimedWait(uint16_t msecs)
{
    DPS_TimedWaitForEvent(event, msecs);
}

static void Wait(void)
{
    DPS_WaitForEvent(event);
}

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    const DPS_KeyId* keyId = DPS_PublicationGetSenderKeyId(pub);
    size_t numTopics;
    size_t i;
    DPS_Status ret;

    if (!IsAllowed(keyId, PUB, pub)) {
        DPS_ERRPRINT("Unauthorized publication\n");
        return;
    }

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
    const DPS_KeyId* keyId = DPS_AckGetSenderKeyId(pub);

    if (!IsAllowed(keyId, ACK, pub)) {
        DPS_ERRPRINT("Unauthorized acknowledgement\n");
        return;
    }

    DPS_PRINT("Ack %s(%d)\n", DPS_UUIDToString(pubId), sn);
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

int main(int argc, char** argv)
{
    char** arg = argv + 1;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    const char* user = NULL;
    char* subs[MAX_TOPICS];
    size_t numSubs = 0;
    char* pubs[MAX_TOPICS];
    size_t numPubs = 0;
    DPS_AcknowledgementHandler ackHandler = AcknowledgementHandler;
    DPS_NodeAddress* listenAddr = NULL;
    DPS_Node* node = NULL;
    const Id* self = NULL;
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Subscription* subscription = NULL;
    DPS_Publication* publication = NULL;
    const Id* id;
    DPS_Status ret = DPS_OK;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
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
        } else if (AddressArg("-l", &arg, &argc, &listenAddr)) {
        } else {
            goto Usage;
        }
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

    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), &self->keyId);
    if (!node) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_StartNode(node, mcast, listenAddr);
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
        for (id = Ids; id->keyId.id; ++id) {
            if (IsAllowed(&id->keyId, SUB, publication)) {
                ret = DPS_PublicationAddSubId(publication, &id->keyId);
                if (ret != DPS_OK) {
                    return ret;
                }
            }
        }
    }

    if (publication) {
        ret = DPS_Publish(publication, NULL, 0, 0);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }

    DPS_PRINT("Ready\n");
    Wait();

Exit:
    DPS_DestroyPublication(publication);
    DPS_DestroySubscription(subscription);
    ret = DPS_DestroyNode(node, OnNodeDestroyed, event);
    if (ret == DPS_OK) {
        DPS_WaitForEvent(event);
    }
    DPS_DestroyMemoryKeyStore(keyStore);
    DPS_DestroyEvent(event);
    DPS_DestroyAddress(listenAddr);
    DPS_PRINT("Exiting\n");
    return ret;

Usage:
    DPS_PRINT("Usage %s [-d] [-u <user>] [-s <topic>] [-p <topic>] [-l <address>]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -u: Set user ID.\n");
    DPS_PRINT("       -s: Subscribe to topic.  May be repeated.\n");
    DPS_PRINT("       -p: Publish to topic.  May be repeated.\n");
    DPS_PRINT("       -l: Address to listen on for incoming connections.\n");
    return DPS_ERR_FAILURE;
}
