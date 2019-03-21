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
#include <dps/event.h>
#ifndef _WIN32
#include <netinet/in.h>
#endif
/** [Prerequisites] */
#include <dps/dbg.h>
#include <dps/dps.h>
/** [Prerequisites] */

#ifdef _WIN32
#define SLEEP(t) Sleep(t)
#else
extern void usleep(int);
#define SLEEP(t) usleep((t) * 1000)
#endif

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

/** [Pre-shared key] */
#define BYTE_STR(s) { (const uint8_t*)s, sizeof(s) - 1 }
static const DPS_Key PSK = { DPS_KEY_SYMMETRIC, { .symmetric = BYTE_STR("1234") } };
static const DPS_KeyId PSK_ID = BYTE_STR("Tutorial Network PSK");
/** [Pre-shared key] */

/** [Certificates] */
extern const char* CA_CERTIFICATE;
typedef struct {
    DPS_KeyId keyId;
    DPS_Key key;
} Certificate;
extern const Certificate CERTIFICATES[];
#include "tutorial_certs.c"
/** [Certificates] */

/** [Symmetric key] */
static const uint8_t AES_256_KEY[DPS_AES_256_KEY_LEN] = {
    0x37, 0xf9, 0x6f, 0x85, 0x72, 0x0c, 0xa0, 0x1b, 0x85, 0x51, 0x50, 0x45, 0x22, 0xa7, 0x30, 0x55,
    0x4f, 0x05, 0x9c, 0xc4, 0xf4, 0xbb, 0xa6, 0x37, 0xfc, 0x0a, 0x90, 0x53, 0x64, 0xe1, 0xb7, 0x9c
};
static const DPS_Key SYMMETRIC_KEY = { DPS_KEY_SYMMETRIC, { .symmetric = { AES_256_KEY, DPS_AES_256_KEY_LEN } } };
static const DPS_KeyId SYMMETRIC_KEY_ID = BYTE_STR("Tutorial Symmetric Key");
/** [Symmetric key] */

/** [Asymmetric key] */
extern const DPS_Key ASYMMETRIC_KEY;
static const DPS_KeyId ASYMMETRIC_KEY_ID = BYTE_STR("Tutorial Asymmetric Key");
/** [Asymmetric key] */

static DPS_Node* CreateNode(void);
static DPS_Node* CreateNodeWithNetworkPSK(void);
static DPS_Node* CreateNodeWithNetworkCert(const DPS_KeyId* nodeId);
static DPS_Node* CreateNodeWithSymmetricKeyStore(void);
static DPS_Node* CreateNodeWithAsymmetricKeyStore(void);
static DPS_Node* CreateNodeWithAuthenticatedSender(const DPS_KeyId* nodeId);
static DPS_Status StartMulticastNode(DPS_Node* node);
static DPS_Status StartUnicastNode(DPS_Node* node, uint16_t listenPort);
static DPS_Status StartNode(DPS_Node* node, int mcastPub, const char* listenText);
static void LinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data);
static DPS_Status Publish(DPS_Node* node, const char* security, DPS_Publication** createdPub);
static DPS_Status PublishAck(DPS_Node* node, const char* security, DPS_Publication** createdPub);
static DPS_Status PublishAuthAck(DPS_Node* node, const char* security, DPS_Publication** createdPub);
static DPS_Status Subscribe(DPS_Node* node, int ack, int auth, DPS_Subscription** createdSub);
static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t len);
static void PublicationAckHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                                  uint8_t* payload, size_t len);
static void AuthPublicationAckHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                                      uint8_t* payload, size_t len);
static void AcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len);
static void AuthAcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len);
static DPS_Status PskAndIdHandler(DPS_KeyStoreRequest* request);
static DPS_Status PskHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);
static DPS_Status CertificateHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);
static DPS_Status CertificateAuthoritiesHandler(DPS_KeyStoreRequest* request);
static DPS_Status SymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);
static DPS_Status EphemeralSymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key);
static DPS_Status AsymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);
static DPS_Status EphemeralAsymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key);
static DPS_Status KeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId);
static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key);
static void DestroyNode(DPS_Node* node);

static void Usage(int argc, char** argv)
{
    DPS_PRINT("Usage %s [-d] [-l <port>] [-p <port>] [-x <network-psk|network-cert|symmetric|asymmetric>] [auth] [publish|subscribe] [ack]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -l: Port to listen on.  This may be 0 to request an ephemeral port.\n");
    DPS_PRINT("       -p: Port to link to.\n");
    DPS_PRINT("       -x: Secure the node.\n");
}

int main(int argc, char** argv)
{
    DPS_Node* node = NULL;
    DPS_Publication* pub = NULL;
    DPS_Subscription* sub = NULL;
    int publish = DPS_FALSE;
    int subscribe = DPS_FALSE;
    int ack = DPS_FALSE;
    int listenPort = -1;
    const char* listenText = NULL;
    int linkPort = 0;
    const char* linkText = NULL;
    const char *security = 0;
    int auth = DPS_FALSE;
    char* endp;
    int i;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "publish")) {
            publish = DPS_TRUE;
        } else if (!strcmp(argv[i], "subscribe")) {
            subscribe = DPS_TRUE;
        } else if (!strcmp(argv[i], "ack")) {
            ack = DPS_TRUE;
        } else if (!strcmp(argv[i], "-l") && ((i + 1) < argc)) {
            listenPort = strtol(argv[i + 1], &endp, 10);
            if (*endp) {
                listenText = argv[i + 1];
            }
            ++i;
        } else if (!strcmp(argv[i], "-p") && ((i + 1) < argc)) {
            linkPort = strtol(argv[i + 1], &endp, 10);
            if (*endp) {
                linkText = argv[i + 1];
            }
            ++i;
        } else if (!strcmp(argv[i], "-x") && ((i + 1) < argc)) {
            security = argv[i + 1];
            ++i;
        } else if (!strcmp(argv[i], "auth")) {
            auth = DPS_TRUE;
        } else if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        } else {
            Usage(argc, argv);
            return EXIT_FAILURE;
        }
    }

    const DPS_KeyId publisherId = BYTE_STR("Tutorial Publisher Node");
    const DPS_KeyId subscriberId = BYTE_STR("Tutorial Subscriber Node");
    const DPS_KeyId forwarderId = BYTE_STR("Tutorial Node");
    const DPS_KeyId* nodeId = NULL;
    if (publish) {
        nodeId = &publisherId;
    } else if (subscribe) {
        nodeId = &subscriberId;
    } else {
        nodeId = &forwarderId;
    }

    if (security == NULL) {
        node = CreateNode();
    } else if (!strcmp(security, "network-psk")) {
        node = CreateNodeWithNetworkPSK();
    } else if (!strcmp(security, "network-cert")) {
        node = CreateNodeWithNetworkCert(nodeId);
    } else if (!strcmp(security, "symmetric")) {
        if (auth) {
            node = CreateNodeWithAuthenticatedSender(nodeId);
        } else {
            node = CreateNodeWithSymmetricKeyStore();
        }
    } else if (!strcmp(security, "asymmetric")) {
        if (auth) {
            node = CreateNodeWithAuthenticatedSender(nodeId);
        } else {
            node = CreateNodeWithAsymmetricKeyStore();
        }
    }
    if (!node) {
        goto Exit;
    }

    if (linkText || listenText) {
        ret = StartNode(node, DPS_MCAST_PUB_DISABLED, listenText);
    } else if (linkPort || (listenPort >= 0)) {
        if (listenPort == -1) {
            listenPort = 0;
        }
        ret = StartUnicastNode(node, listenPort);
    } else {
        ret = StartMulticastNode(node);
    }
    if (ret != DPS_OK) {
        goto Exit;
    }

    if (linkText) {
        ret = DPS_Link(node, linkText, LinkComplete, NULL);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /* Wait for link to complete */
        SLEEP(1000);
    } else if (linkPort) {
        /** [Linking to a node] */
        char addrText[24];
        snprintf(addrText, sizeof(addrText), "127.0.0.1:%d", linkPort);
        ret = DPS_Link(node, addrText, LinkComplete, NULL);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /** [Linking to a node] */
        /* Wait for link to complete */
        SLEEP(1000);
    }

    if (publish && ack) {
        if (auth) {
            ret = PublishAuthAck(node, security, &pub);
        } else {
            ret = PublishAck(node, security, &pub);
        }
    } else if (publish) {
        ret = Publish(node, security, &pub);
    } else if (subscribe) {
        ret = Subscribe(node, ack, auth, &sub);
    }
    if (ret != DPS_OK) {
        goto Exit;
    }

    /* Sleep until user kills us */
    for (;;) {
        SLEEP(1000);
    }

Exit:
    DPS_DestroyPublication(pub);
    DPS_DestroySubscription(sub);
    DPS_KeyStore* keyStore = (DPS_KeyStore*)DPS_GetNodeData(node);
    DPS_DestroyKeyStore(keyStore);
    DestroyNode(node);
    return EXIT_SUCCESS;
}

static DPS_Node* CreateNode(void)
{
    /** [Creating a node] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = NULL;
    const DPS_KeyId* keyId = NULL;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a node] */

Exit:
    return node;
}

static DPS_Node* CreateNodeWithNetworkPSK(void)
{
    /** [Creating a secure node with a network PSK] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = DPS_CreateKeyStore(PskAndIdHandler, PskHandler, NULL, NULL);
    const DPS_KeyId* keyId = NULL;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a secure node with a network PSK] */
    DPS_SetNodeData(node, keyStore);

Exit:
    return node;
}

static DPS_Node* CreateNodeWithNetworkCert(const DPS_KeyId* nodeId)
{
    /** [Creating a secure node with a network certificate] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = DPS_CreateKeyStore(NULL, CertificateHandler,
                                                NULL, CertificateAuthoritiesHandler);
    const DPS_KeyId* keyId = nodeId;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a secure node with a network certificate] */
    DPS_SetNodeData(node, keyStore);

Exit:
    return node;
}

static DPS_Node* CreateNodeWithSymmetricKeyStore(void)
{
    /** [Creating a node with symmetric key handlers] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = DPS_CreateKeyStore(NULL, SymmetricKeyHandler, EphemeralSymmetricKeyHandler, NULL);
    const DPS_KeyId* keyId = NULL;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a node with symmetric key handlers] */
    DPS_SetNodeData(node, keyStore);

Exit:
    return node;
}

static DPS_Node* CreateNodeWithAsymmetricKeyStore(void)
{
    const char *separators = "/.";
    DPS_KeyStore* keyStore = DPS_CreateKeyStore(NULL, AsymmetricKeyHandler, EphemeralAsymmetricKeyHandler, NULL);
    const DPS_KeyId* keyId = NULL;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    DPS_SetNodeData(node, keyStore);

Exit:
    return node;
}

static DPS_Node* CreateNodeWithAuthenticatedSender(const DPS_KeyId* nodeId)
{
    /** [Creating a secure node with an authenticated sender] */
    const char *separators = "/.";
    DPS_KeyStore* keyStore = DPS_CreateKeyStore(NULL, KeyHandler, EphemeralKeyHandler, NULL);
    const DPS_KeyId* keyId = nodeId;
    DPS_Node* node = DPS_CreateNode(separators, keyStore, keyId);
    if (!node) {
        goto Exit;
    }
    /** [Creating a secure node with an authenticated sender] */
    DPS_SetNodeData(node, keyStore);

Exit:
    return node;
}

static DPS_Status StartNode(DPS_Node* node, int mcastPub, const char* listenText)
{
    DPS_Status ret;
    DPS_NodeAddress* listenAddr = NULL;

    if (listenText) {
        listenAddr = DPS_CreateAddress();
        if (!listenAddr) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        DPS_SetAddress(listenAddr, listenText);
    }
    ret = DPS_StartNode(node, mcastPub, listenAddr);
    if (ret != DPS_OK) {
        goto Exit;
    }
    DPS_PRINT("Node is listening on %s\n", DPS_GetListenAddressString(node));

 Exit:
    DPS_DestroyAddress(listenAddr);
    return ret;
}

static DPS_Status StartMulticastNode(DPS_Node* node)
{
    /** [Starting a node] */
    int mcastPub = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    DPS_Status ret = DPS_StartNode(node, mcastPub, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Starting a node] */
    DPS_PRINT("Node is listening on %s\n", DPS_GetListenAddressString(node));

 Exit:
    return ret;
}

static DPS_Status StartUnicastNode(DPS_Node* node, uint16_t port)
{
    DPS_Status ret;
    char addrText[24];
    /** [Starting a unicast node] */
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    DPS_NodeAddress* listenAddr = DPS_CreateAddress();
    if (!listenAddr) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    snprintf(addrText, sizeof(addrText), "[::]:%d", port);
    DPS_SetAddress(listenAddr, addrText);
    ret = DPS_StartNode(node, mcastPub, listenAddr);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Starting a unicast node] */
    DPS_PRINT("Node is listening on %s\n", DPS_GetListenAddressString(node));

 Exit:
    DPS_DestroyAddress(listenAddr);
    return ret;
}

/** [Linking complete] */
static void LinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    DPS_PRINT("Node is linked to %s\n", DPS_NodeAddrToString(addr));
}
/** [Linking complete] */

static DPS_Status SendPublication(DPS_Publication* pub)
{
    DPS_Status ret;

    /** [Sending a publication] */
    const char* payload = "Hello";
    size_t numPayloadBytes = strlen(payload) + 1;
    int16_t ttl = 0;
    ret = DPS_Publish(pub, (const uint8_t*)payload, numPayloadBytes, ttl);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Sending a publication] */

Exit:
    return ret;
}

static DPS_Status PublicationAddSubId(DPS_Publication* pub, const char* security)
{
    DPS_Status ret = DPS_OK;

    if (security) {
        if (!strcmp(security, "symmetric")) {
            /** [Protecting the payload] */
            ret = DPS_PublicationAddSubId(pub, &SYMMETRIC_KEY_ID);
            if (ret != DPS_OK) {
                goto Exit;
            }
            /** [Protecting the payload] */
        } else if (!strcmp(security, "asymmetric")) {
            ret = DPS_PublicationAddSubId(pub, &ASYMMETRIC_KEY_ID);
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
    }

Exit:
    return ret;
}

static DPS_Status Publish(DPS_Node* node, const char* security, DPS_Publication** createdPub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Creating a publication] */
    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Creating a publication] */

    ret = PublicationAddSubId(pub, security);
    if (ret != DPS_OK) {
        goto Exit;
    }

    ret = SendPublication(pub);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    *createdPub = pub;
    return ret;
}

static DPS_Status PublishAck(DPS_Node* node, const char* security, DPS_Publication** createdPub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Requesting an acknowledgement] */
    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL,
                              AcknowledgementHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }
    /** [Requesting an acknowledgement] */

    ret = PublicationAddSubId(pub, security);
    if (ret != DPS_OK) {
        goto Exit;
    }

    ret = SendPublication(pub);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    *createdPub = pub;
    return ret;
}

static DPS_Status PublishAuthAck(DPS_Node* node, const char* security, DPS_Publication** createdPub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL,
                              AuthAcknowledgementHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }

    ret = PublicationAddSubId(pub, security);
    if (ret != DPS_OK) {
        goto Exit;
    }

    ret = SendPublication(pub);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:
    *createdPub = pub;
    return ret;
}

static DPS_Status Subscribe(DPS_Node* node, int ack, int auth, DPS_Subscription** createdSub)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    /** [Creating a subscription] */
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    DPS_Subscription* sub = DPS_CreateSubscription(node, topics, numTopics);
    if (!sub) {
        goto Exit;
    }
    /** [Creating a subscription] */

    if (ack) {
        if (auth) {
            ret = DPS_Subscribe(sub, AuthPublicationAckHandler);
        } else {
            ret = DPS_Subscribe(sub, PublicationAckHandler);
        }
        if (ret != DPS_OK) {
            goto Exit;
        }
    } else {
        /** [Subscribing] */
        ret = DPS_Subscribe(sub, PublicationHandler);
        if (ret != DPS_OK) {
            goto Exit;
        }
        /** [Subscribing] */
    }

Exit:
    *createdSub = sub;
    return ret;
}

/** [Receiving a publication] */
static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                               uint8_t* payload, size_t numPayloadBytes)
{
    size_t i;

    for (i = 0; i < DPS_SubscriptionGetNumTopics(sub); ++i) {
        const char* topic = DPS_SubscriptionGetTopic(sub, i);
        DPS_PRINT("subscription topic[%ld]=%s\n", i, topic);
    }

    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    DPS_PRINT("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    DPS_PRINT("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        DPS_PRINT("publication topic[%ld]=%s\n", i, topic);
    }

    DPS_PRINT("payload=%.*s\n", numPayloadBytes, payload);
}
/** [Receiving a publication] */

static void PublicationAckHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                                  uint8_t* payload, size_t numPayloadBytes)
{
    PublicationHandler(sub, pub, payload, numPayloadBytes);

    /** [Sending an acknowledgement] */
    if (DPS_PublicationIsAckRequested(pub)) {
        const char* payload = "World";
        size_t numPayloadBytes = strlen(payload) + 1;
        DPS_Status ret = DPS_AckPublication(pub, (const uint8_t*)payload, numPayloadBytes);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    /** [Sending an acknowledgement] */

Exit:
    return;
}

static void AuthPublicationAckHandler(DPS_Subscription* sub, const DPS_Publication* pub,
                                      uint8_t* payload, size_t numPayloadBytes)
{
    PublicationAckHandler(sub, pub, payload, numPayloadBytes);

    /** [Authenticating a publication] */
    const DPS_KeyId* keyId = DPS_PublicationGetSenderKeyId(pub);
    DPS_PRINT("sender=%.*s\n", keyId->len, keyId->id);
    /** [Authenticating a publication] */
}

/** [Receiving an acknowledgement] */
static void AcknowledgementHandler(DPS_Publication* pub,
                                   uint8_t* payload, size_t numPayloadBytes)
{
    size_t i;

    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    DPS_PRINT("uuid=%s\n", DPS_UUIDToString(uuid));

    uint32_t n = DPS_PublicationGetSequenceNum(pub);
    DPS_PRINT("sequence number=%d\n", n);

    for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
        const char* topic = DPS_PublicationGetTopic(pub, i);
        DPS_PRINT("publication topic[%ld]=%s\n", i, topic);
    }

    DPS_PRINT("payload=%.*s\n", numPayloadBytes, payload);
}
/** [Receiving an acknowledgement] */

static void AuthAcknowledgementHandler(DPS_Publication* pub,
                                       uint8_t* payload, size_t numPayloadBytes)
{
    AcknowledgementHandler(pub, payload, numPayloadBytes);

    /** [Authenticating an acknowledgement] */
    const DPS_KeyId* keyId = DPS_AckGetSenderKeyId(pub);
    DPS_PRINT("sender=%.*s\n", keyId->len, keyId->id);
    /** [Authenticating an acknowledgement] */
}

/** [PSK and ID handler] */
static DPS_Status PskAndIdHandler(DPS_KeyStoreRequest* request)
{
    return DPS_SetKeyAndId(request, &PSK, &PSK_ID);
}
/** [PSK and ID handler] */

/** [PSK handler] */
static int IsSameKeyId(const DPS_KeyId* a, const DPS_KeyId* b)
{
    return (a->len == b->len) && !memcmp(a->id, b->id, a->len);
}

static DPS_Status PskHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    if (IsSameKeyId(keyId, &PSK_ID)) {
        return DPS_SetKey(request, &PSK);
    }
    return DPS_ERR_MISSING;
}
/** [PSK handler] */

/** [Certificate handler] */
static DPS_Status CertificateHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    const Certificate* certificate;
    for (certificate = CERTIFICATES; certificate->keyId.id; ++certificate) {
        if (IsSameKeyId(keyId, &certificate->keyId)) {
            return DPS_SetKey(request, &certificate->key);
        }
    }
    return DPS_ERR_MISSING;
}
/** [Certificate handler] */

/** [Certificate authorities handler] */
static DPS_Status CertificateAuthoritiesHandler(DPS_KeyStoreRequest* request)
{
    return DPS_SetCA(request, CA_CERTIFICATE);
}
/** [Certificate authorities handler] */

/** [Symmetric key handler] */
static DPS_Status SymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    if (IsSameKeyId(keyId, &SYMMETRIC_KEY_ID)) {
        return DPS_SetKey(request, &SYMMETRIC_KEY);
    }
    return DPS_ERR_MISSING;
}
/** [Symmetric key handler] */

/* This is only for purposes of the tutorial, a real application must return truly random bytes */
static void GenerateRandomKey(uint8_t key[DPS_AES_256_KEY_LEN])
{
    static const uint8_t bytes[DPS_AES_256_KEY_LEN] = {
        0x33, 0x69, 0xd9, 0x48, 0x36, 0x87, 0x95, 0x44, 0x97, 0x67, 0xf7, 0x09, 0xdc, 0x86, 0xae, 0xe7,
        0x93, 0x50, 0x09, 0xe9, 0x2c, 0x55, 0xfc, 0x4e, 0x43, 0xf6, 0x26, 0xe3, 0xe8, 0x3e, 0x19, 0x6c
    };
    memcpy(key, bytes, DPS_AES_256_KEY_LEN);
}

/** [Ephemeral symmetric key handler] */
static DPS_Status EphemeralSymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    if (key->type == DPS_KEY_SYMMETRIC) {
        uint8_t key[DPS_AES_256_KEY_LEN];
        GenerateRandomKey(key);
        DPS_Key ephemeralKey = { DPS_KEY_SYMMETRIC, { .symmetric = { key, DPS_AES_256_KEY_LEN } } };
        return DPS_SetKey(request, &ephemeralKey);
    }
    return DPS_ERR_MISSING;
}
/** [Ephemeral symmetric key handler] */

static DPS_Status AsymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    if (IsSameKeyId(keyId, &ASYMMETRIC_KEY_ID)) {
        return DPS_SetKey(request, &ASYMMETRIC_KEY);
    }
    return DPS_ERR_MISSING;
}

/* This is only for purposes of the tutorial, a real application must return a true ephemeral key */
static void GenerateEphemeralKey(DPS_ECCurve curve, uint8_t x[66], uint8_t y[66], uint8_t d[66])
{
    static const uint8_t _x[] = {
        0x01, 0xb3, 0xed, 0xa2, 0x32, 0xdd, 0xd8, 0xbf, 0x6a, 0x84, 0x16, 0x33, 0xf3, 0x3c, 0xf4, 0x61,
        0x2a, 0x8f, 0x6b, 0x5d, 0xa2, 0xfc, 0xe5, 0x12, 0x8f, 0x97, 0x5b, 0xf1, 0xdd, 0x71, 0x95, 0x78,
        0x1f, 0x04, 0xfa, 0x43, 0xfe, 0x67, 0x58, 0x70, 0xcf, 0x73, 0xbd, 0x36, 0x3d, 0xb5, 0xe7, 0xc0,
        0xdb, 0xbe, 0xf9, 0xef, 0xb7, 0x05, 0xe2, 0x3c, 0x16, 0xdb, 0x67, 0x18, 0x9f, 0x84, 0x9f, 0xd6,
        0x60, 0x72
    };
    static const uint8_t _y[] = {
        0x00, 0x84, 0xaa, 0xe6, 0x0e, 0xdb, 0x33, 0x05, 0xa5, 0xbb, 0x35, 0x4c, 0x63, 0xf9, 0xc2, 0x39,
        0x8f, 0x73, 0xd7, 0x7a, 0x24, 0x3f, 0x2d, 0x72, 0x2f, 0x85, 0x86, 0xd9, 0x93, 0x09, 0x88, 0x67,
        0x57, 0x30, 0x20, 0x51, 0x36, 0xd5, 0xf7, 0xc5, 0x94, 0xdb, 0xca, 0x76, 0x2b, 0xe0, 0x29, 0xc7,
        0x76, 0x8c, 0x28, 0x75, 0x24, 0x16, 0x8b, 0xc9, 0xfc, 0xfe, 0xbe, 0xed, 0x0e, 0x6f, 0xe1, 0x7c,
        0x9b, 0x02
    };
    static const uint8_t _d[] = {
        0x00, 0x7e, 0xb9, 0x12, 0x5f, 0xb2, 0x9c, 0x27, 0x4d, 0x00, 0xfb, 0xd5, 0xe4, 0x03, 0x17, 0x02,
        0xe1, 0xb8, 0x14, 0x31, 0x8c, 0x75, 0x2f, 0xae, 0xae, 0x94, 0xfd, 0x8f, 0x33, 0xb4, 0x0b, 0x1a,
        0x35, 0xca, 0xa9, 0xa6, 0x3b, 0xc7, 0x65, 0x98, 0xaf, 0xc3, 0x26, 0x4e, 0x53, 0xbc, 0x3c, 0xfd,
        0x33, 0x7c, 0x7a, 0xee, 0x02, 0xd6, 0x16, 0x99, 0xd9, 0x54, 0xf7, 0x67, 0xfd, 0x93, 0xa0, 0xaa,
        0x18, 0x5b
    };
    memcpy(x, _x, 66);
    memcpy(y, _y, 66);
    memcpy(d, _d, 66);
}

/** [Ephemeral asymmetric key handler] */
static DPS_Status EphemeralAsymmetricKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    if (key->type == DPS_KEY_SYMMETRIC) {
        uint8_t key[DPS_AES_256_KEY_LEN];
        GenerateRandomKey(key);
        DPS_Key ephemeralKey = { DPS_KEY_SYMMETRIC, { .symmetric = { key, DPS_AES_256_KEY_LEN } } };
        return DPS_SetKey(request, &ephemeralKey);
    } else if (key->type == DPS_KEY_EC) {
        uint8_t x[66], y[66], d[66];
        GenerateEphemeralKey(key->ec.curve, x, y, d);
        DPS_Key ephemeralKey = { DPS_KEY_EC, { .ec = { key->ec.curve, x, y, d } } };
        return DPS_SetKey(request, &ephemeralKey);
    }
    return DPS_ERR_MISSING;
}
/** [Ephemeral asymmetric key handler] */

/** [Key handler] */
static DPS_Status KeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    const Certificate* certificate;
    for (certificate = CERTIFICATES; certificate->keyId.id; ++certificate) {
        if (IsSameKeyId(keyId, &certificate->keyId)) {
            return DPS_SetKey(request, &certificate->key);
        }
    }
    if (IsSameKeyId(keyId, &SYMMETRIC_KEY_ID)) {
        return DPS_SetKey(request, &SYMMETRIC_KEY);
    }
    if (IsSameKeyId(keyId, &ASYMMETRIC_KEY_ID)) {
        return DPS_SetKey(request, &ASYMMETRIC_KEY);
    }
    return DPS_ERR_MISSING;
}
/** [Key handler] */

/** [Ephemeral key handler] */
static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    if (key->type == DPS_KEY_SYMMETRIC) {
        uint8_t key[DPS_AES_256_KEY_LEN];
        GenerateRandomKey(key);
        DPS_Key ephemeralKey = { DPS_KEY_SYMMETRIC, { .symmetric = { key, DPS_AES_256_KEY_LEN } } };
        return DPS_SetKey(request, &ephemeralKey);
    } else if (key->type == DPS_KEY_EC) {
        uint8_t x[66], y[66], d[66];
        GenerateEphemeralKey(key->ec.curve, x, y, d);
        DPS_Key ephemeralKey = { DPS_KEY_EC, { .ec = { key->ec.curve, x, y, d } } };
        return DPS_SetKey(request, &ephemeralKey);
    }
    return DPS_ERR_MISSING;
}
/** [Ephemeral key handler] */

static void NodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_ERR_OK);
}

static void DestroyNode(DPS_Node* node)
{
    DPS_Status ret;
    DPS_Event* event = DPS_CreateEvent();
    ret = DPS_DestroyNode(node, NodeDestroyed, event);
    if (ret == DPS_OK) {
        DPS_WaitForEvent(event);
    }
    DPS_DestroyEvent(event);
}

/** [Defining a policy] */
typedef struct {
    const char *topic;
    const DPS_KeyId keyId;
    enum {
        PUB = (1<<0),
        SUB = (1<<1),
        ACK = (1<<2)
    } bits;
} AccessControlEntry;

static const AccessControlEntry AccessControlList[] = {
    { "a/b/c/d", BYTE_STR("alice"), PUB       },
    { "a/b/c/d", BYTE_STR("bob"),   SUB | ACK },
    { "a/b/c/d", BYTE_STR("trudy"), SUB       },
    { NULL,      { NULL, 0 },       0         }
};

static int IsAllowed(const DPS_KeyId* keyId, int bits, const DPS_Publication* pub)
{
    const AccessControlEntry* ace;
    for (ace = AccessControlList; ace->keyId.id; ++ace) {
        if (IsSameKeyId(keyId, &ace->keyId) && (bits & ace->bits)) {
            size_t i;
            for (i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
                if (!strcmp(ace->topic, DPS_PublicationGetTopic(pub, i))) {
                    return DPS_TRUE;
                }
            }
        }
    }
    return DPS_FALSE;
}
/** [Defining a policy] */

static void AccessControlledPublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    /** [Implementing publication control] */
    const DPS_KeyId* keyId = DPS_PublicationGetSenderKeyId(pub);
    if (!IsAllowed(keyId, PUB, pub)) {
        DPS_PRINT("Rejecting publication\n");
        return;
    }
    /* Proceed with application handling of publication... */
    /** [Implementing publication control] */
}

static void AccessControlledAcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    /** [Implementing acknowledgement control] */
    const DPS_KeyId* keyId = DPS_AckGetSenderKeyId(pub);
    if (!IsAllowed(keyId, ACK, pub)) {
        DPS_ERRPRINT("Rejecting acknowledgement\n");
        return;
    }
    /* Proceed with application handling of acknowledgement... */
    /** [Implementing acknowledgement control] */
}

static DPS_Status PublishWithAccessControl(DPS_Node* node)
{
    DPS_Status ret = DPS_ERR_RESOURCES;

    DPS_Publication* pub = DPS_CreatePublication(node);
    if (!pub) {
        goto Exit;
    }
    const char* topics[] = {
        "a/b/c/d"
    };
    size_t numTopics = A_SIZEOF(topics);
    int noWildCard = DPS_FALSE;
    /** [Implementing subscription control] */
    ret = DPS_InitPublication(pub, topics, numTopics, noWildCard, NULL, AcknowledgementHandler);
    if (ret != DPS_OK) {
        goto Exit;
    }
    const AccessControlEntry* ace;
    for (ace = AccessControlList; ace->keyId.id; ++ace) {
        if (IsAllowed(&ace->keyId, SUB, pub)) {
            ret = DPS_PublicationAddSubId(pub, &ace->keyId);
            if (ret != DPS_OK) {
                goto Exit;
            }
        }
    }
    /** [Implementing subscription control] */

Exit:
    return ret;
}
