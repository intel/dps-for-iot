#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <network.h>
#include <dps.h>
#include <bitvec.h>
#include <uv.h>

static void OnMatch(DPS_Node* node, DPS_Subscription* subscription, const char** topics, size_t numTopics, const DPS_NodeAddress* addr, uint8_t* data, size_t len)
{
    size_t i;

    DPS_PRINT("Got match from %s for:\n    ", DPS_NodeAddressText(addr));
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" & ");
        }
        DPS_PRINT("%s", topics[i]);
    }
    DPS_PRINT("\n");
    if (data) {
        DPS_PRINT("%.*s\n", len, data);
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
    int mcastListen = DPS_FALSE;
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
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            host = *arg++;
            continue;
        }
        if (strcmp(*arg, "-m") == 0) {
            ++arg;
            mcastListen = DPS_TRUE;
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
    if (numTopics == 0) {
        DPS_PRINT("%s: Need a least one topic to subscribe to\n", *argv);
        return 1;
    }

    ret = DPS_Configure(bitLen, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    mcastListen |= (host == NULL) && (connectPort == NULL);

    node = DPS_InitNode(mcastListen, listenPort, "/.");
    if (!node) {
        DPS_ERRPRINT("Failed to initialize node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    ret = DPS_Subscribe(node, topics, numTopics, OnMatch, &subscription);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
        return 1;
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
    DPS_PRINT("Usage %s [-p <portnum>] [-a <hostname>] [-l <listen port] [-m] [-d] topic1 topic2 ... topicN\n", *argv);
    return 1;
}
