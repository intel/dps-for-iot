#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <network.h>
#include <dps.h>
#include <bitvec.h>
#include <uv.h>

static int sendAck = DPS_FALSE;

static uint8_t AckMsg[] = "This is an ACK";

static void OnPubMatch(DPS_Node* node, DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(node, pub);
    uint32_t serialNumber = DPS_PublicationGetSerialNumber(node, pub);
    size_t i;
    size_t numTopics = DPS_SubscriptionGetNumTopics(node, sub);

    DPS_PRINT("Pub %s(%d) matches:\n    ", DPS_UUIDToString(pubId), serialNumber);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" & ");
        }
        DPS_PRINT("%s", DPS_SubscriptionGetTopic(node, sub, i));
    }
    DPS_PRINT("\n");
    if (data) {
        DPS_PRINT("%.*s\n", len, data);
    }
    if (sendAck) {
        DPS_Status ret = DPS_AcknowledgePublication(node, pubId, serialNumber, AckMsg, sizeof(AckMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void OnIdle(uv_idle_t* handle)
{
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_PRINT("Listening on port %d\n", DPS_GetPortNumber(node));
    uv_idle_stop(handle);
}

static int IntArg(char* opt, char*** argp, int* argcp, int* val, uint32_t min, uint32_t max)
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
    char* topics[64];
    char** arg = ++argv;
    size_t numTopics = 0;
    DPS_Node* node;
    DPS_Subscription* subscription;
    DPS_NodeAddress addr;
    uv_loop_t* loop;
    uv_idle_t idler;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = NULL;
    int listenPort = 0;
    const char* connectPort = NULL;
    int bitLen = 16 * 1024;
    int numHashes = 4;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-h", &arg, &argc, &numHashes, 2, 16)) {
            continue;
        }
        if (IntArg("-b", &arg, &argc, &bitLen, 64, 8 * 1024 * 1024)) {
            continue;
        }
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            connectPort = *arg++;
            continue;
        }
        if (strcmp(*arg, "-h") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            host = *arg++;
            continue;
        }
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            sendAck = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-m") == 0) {
            ++arg;
            mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
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
        if (numTopics == A_SIZEOF(topics)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }

    ret = DPS_Configure(bitLen, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    if ((host == NULL) && (connectPort == NULL)) {
        mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
    }

    node = DPS_InitNode(mcastPub, listenPort, "/.");
    if (!node) {
        DPS_ERRPRINT("Failed to initialize node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    if (numTopics > 0) {
        ret = DPS_Subscribe(node, topics, numTopics, OnPubMatch, &subscription);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }

    assert(node);
    loop = DPS_GetLoop(node);

    if (host || connectPort) {
        ret = DPS_ResolveAddress(node, host, connectPort, &addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to resolve %s/%s\n", host ? host : "<localhost>", connectPort);
            return 1;
        }
        ret = DPS_Join(node, &addr);
    }

    uv_idle_init(loop, &idler);
    idler.data = node;
    uv_idle_start(&idler, OnIdle);

    return uv_run(loop, UV_RUN_DEFAULT);

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-h <hostname>] [-l <listen port] [-m] [-d] topic1 topic2 ... topicN\n", *argv);
    return 1;
}
