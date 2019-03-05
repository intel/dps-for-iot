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

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

void Fuzz_OnNetReceive(DPS_Node* node, const uint8_t* data, size_t len);

static DPS_MemoryKeyStore* CreateKeyStore()
{
    DPS_MemoryKeyStore* keyStore;
    size_t i;
    const Id* id;

    keyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(keyStore, &NetworkKeyId, &NetworkKey);
    for (i = 0; i < NUM_KEYS; ++i) {
        DPS_SetContentKey(keyStore, &PskId[i], &Psk[i]);
    }
    DPS_SetTrustedCA(keyStore, TrustedCAs);
    for (id = Ids; id->keyId.id; ++id) {
        DPS_SetCertificate(keyStore, id->cert, id->privateKey, id->password);
    }
    return keyStore;
}

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t len)
{
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
    DPS_Event* event = NULL;
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* node = NULL;
    DPS_Subscription* subs[] = { NULL, NULL, NULL };
    const char *topics[] = { "+/#", "+.#", "+" };
    DPS_Status ret;
    size_t i;

    event = DPS_CreateEvent();
    if (!event) {
        goto Exit;
    }
    keyStore = CreateKeyStore();
    if (!keyStore) {
        goto Exit;
    }
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), NULL);
    if (!node) {
        goto Exit;
    }
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    for (i = 0; i < A_SIZEOF(topics); ++i) {
        subs[i] = DPS_CreateSubscription(node, &topics[i], 1);
        if (!subs[i]) {
            goto Exit;
        }
        ret = DPS_Subscribe(subs[i], PublicationHandler);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }

    Fuzz_OnNetReceive(node, data, len);

Exit:
    for (i = 0; i < A_SIZEOF(subs); ++i) {
        if (subs[i]) {
            DPS_DestroySubscription(subs[i]);
        }
    }
    if (node) {
        ret = DPS_DestroyNode(node, OnNodeDestroyed, event);
        if (ret == DPS_OK) {
            DPS_WaitForEvent(event);
        }
    }
    if (keyStore) {
        DPS_DestroyMemoryKeyStore(keyStore);
    }
    if (event) {
        DPS_DestroyEvent(event);
    }
    return 0;
}
