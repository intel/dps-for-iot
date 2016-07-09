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
    size_t filterBits = 0;
    size_t numHashes = 4;

    DPS_Debug = 0;

    while (--argc) {
        char* p;
        if (strcmp(*arg, "-b") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            filterBits = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-n") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            numHashes = strtol(*arg++, &p, 10);
            if (*p) {
                goto Usage;
            }
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
        if (strcmp(*arg, "-l") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            listenPort = strtol(*arg++, &p, 10);
            if (*p) {
                DPS_PRINT("Listen port option (-l) requires a decimal number\n");
                goto Usage;
            }
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

    if (filterBits) {
        ret = DPS_Configure(filterBits, numHashes, 16, 10);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Invalid configuration parameters\n");
            goto Usage;
        }
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
