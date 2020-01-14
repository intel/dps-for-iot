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

#include "crypto.h"
#include "keys.h"
#include "test.h"

static DPS_Status GetKeyAndId(DPS_KeyStoreRequest* request)
{
    return DPS_ERR_MISSING;
}

static DPS_Status GetKey(DPS_KeyStoreRequest* request, const DPS_KeyId* id)
{
    return DPS_ERR_MISSING;
}

static DPS_Status GetEphemeralKey(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    return DPS_ERR_MISSING;
}

static DPS_Status GetCA(DPS_KeyStoreRequest* request)
{
    return DPS_ERR_MISSING;
}

static void TestCreateDestroy(void)
{
    DPS_KeyStore* keyStore = NULL;

    keyStore = DPS_CreateKeyStore(GetKeyAndId, GetKey, GetEphemeralKey, GetCA);
    ASSERT(keyStore);
    DPS_DestroyKeyStore(keyStore);
}

static void TestDestroyNull(void)
{
    DPS_KeyStore* keyStore = NULL;

    DPS_DestroyKeyStore(keyStore);
}

static void TestGetSetUserData(void)
{
    DPS_KeyStore* keyStore = NULL;
    void* userData;
    DPS_Status ret;

    /* Set and get user data */
    keyStore = DPS_CreateKeyStore(GetKeyAndId, GetKey, GetEphemeralKey, GetCA);
    ASSERT(keyStore);
    ret = DPS_SetKeyStoreData(keyStore, (void*)1);
    ASSERT(ret == DPS_OK);
    userData = DPS_GetKeyStoreData(keyStore);
    ASSERT(userData == (void*)1);
    DPS_DestroyKeyStore(keyStore);
}

static void TestSetUserDataNull(void)
{
    DPS_KeyStore* keyStore = NULL;
    DPS_Status ret;

    /* Set user data on NULL key store */
    ret = DPS_SetKeyStoreData(keyStore, (void*)1);
    ASSERT(ret != DPS_OK);
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

typedef struct {
    DPS_RBG* rbg;
    int call;
} KeyStoreData;

static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    KeyStoreData* data = (KeyStoreData*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    DPS_Key k;
    DPS_Status ret;

    switch (key->type) {
    case DPS_KEY_SYMMETRIC: {
        uint8_t key[AES_256_KEY_LEN];
        ret = DPS_RandomKey(data->rbg, key);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_SYMMETRIC;
        k.symmetric.key = key;
        k.symmetric.len = AES_256_KEY_LEN;
        return DPS_SetKey(request, &k);
    }
    case DPS_KEY_EC: {
        uint8_t x[EC_MAX_COORD_LEN];
        uint8_t y[EC_MAX_COORD_LEN];
        uint8_t d[EC_MAX_COORD_LEN];
        ret = DPS_EphemeralKey(data->rbg, key->ec.curve, x, y, d);
        if (ret != DPS_OK) {
            return ret;
        }
        k.type = DPS_KEY_EC;
        k.ec.curve = key->ec.curve;
        k.ec.x = x;
        k.ec.y = y;
        k.ec.d = d;
        return DPS_SetKey(request, &k);
    }
    default:
        return DPS_ERR_NOT_IMPLEMENTED;
    }
}

static DPS_Status GetMissingReservedKey(DPS_KeyStoreRequest* request, const DPS_KeyId* id)
{
    KeyStoreData* data = (KeyStoreData*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));

    /*
     * First call is to get recipient algorithm in DPS_PublicationAddSubId,
     * second call is to get the encryption key in DPS_Publish.
     */
    switch (data->call++) {
    case 0:
        /*
         * Return OK without calling DPS_SetKey to trigger RESERVED algorithm case.
         */
        return DPS_OK;
    default:
        return DPS_ERR_MISSING;
    }
}

static DPS_Status GetMissingSymmetricKey(DPS_KeyStoreRequest* request, const DPS_KeyId* id)
{
    KeyStoreData* data = (KeyStoreData*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));

    switch (data->call++) {
    case 0:
        return DPS_SetKey(request, &Psk[0]);
    default:
        return DPS_ERR_MISSING;
    }
}

static DPS_Status GetMissingAsymmetricKey(DPS_KeyStoreRequest* request, const DPS_KeyId* id)
{
    KeyStoreData* data = (KeyStoreData*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    DPS_Key k;

    switch (data->call++) {
    case 0:
        k.type = DPS_KEY_EC_CERT;
        k.cert.cert = Ids[0].cert;
        k.cert.privateKey = Ids[0].privateKey;
        k.cert.password = Ids[0].password;
        return DPS_SetKey(request, &k);
    default:
        return DPS_ERR_MISSING;
    }
}

static void PublishWhenMissingKey(DPS_KeyHandler keyHandler, const DPS_KeyId* keyId)
{
    static const char* topics[] = { __FUNCTION__ };
    static const size_t numTopics = 1;
    KeyStoreData keyStoreData;
    DPS_KeyStore* keyStore = NULL;
    DPS_Node* node = NULL;
    DPS_Publication* pub = NULL;
    DPS_Event* event = NULL;
    DPS_Status ret;

    keyStoreData.call = 0;
    keyStoreData.rbg = DPS_CreateRBG();
    ASSERT(keyStoreData.rbg);
    keyStore = DPS_CreateKeyStore(GetKeyAndId, keyHandler, EphemeralKeyHandler, GetCA);
    ASSERT(keyStore);
    DPS_SetKeyStoreData(keyStore, &keyStoreData);
    node = DPS_CreateNode("/.", keyStore, keyId);
    ASSERT(node);
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_SEND, NULL);
    ASSERT(ret == DPS_OK);
    pub = DPS_CreatePublication(node);
    ASSERT(pub);
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, NULL);
    ASSERT(ret == DPS_OK);

    if (!keyId) {
        ret = DPS_PublicationAddSubId(pub, &PskId[0]);
        ASSERT(ret == DPS_OK);
    }
    ret = DPS_Publish(pub, NULL, 0, 0);
    ASSERT(ret != DPS_OK);

    DPS_DestroyPublication(pub, NULL);
    event = DPS_CreateEvent();
    ASSERT(event);
    DPS_DestroyNode(node, OnNodeDestroyed, event);
    DPS_WaitForEvent(event);
    DPS_DestroyEvent(event);
    DPS_DestroyKeyStore(keyStore);
    DPS_DestroyRBG(keyStoreData.rbg);
}

static void TestPublishWhenMissingSubKey(void)
{
    PublishWhenMissingKey(GetMissingReservedKey, NULL);
    PublishWhenMissingKey(GetMissingSymmetricKey, NULL);
    PublishWhenMissingKey(GetMissingAsymmetricKey, NULL);
}

static void TestPublishWhenMissingSignerKey(void)
{
    PublishWhenMissingKey(GetMissingAsymmetricKey, &Ids[0].keyId);
}

int main(int argc, char** argv)
{
    int i;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    TestCreateDestroy();
    TestDestroyNull();
    TestGetSetUserData();
    TestSetUserDataNull();
    TestPublishWhenMissingSubKey();
    TestPublishWhenMissingSignerKey();

    return EXIT_SUCCESS;
}
