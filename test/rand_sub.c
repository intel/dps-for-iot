#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <network.h>
#include <dps.h>
#include <uv.h>

static void OnPubMatch(DPS_Node* node, DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    size_t i;
    size_t numTopics = DPS_SubscriptionGetNumTopics(node, sub);

    DPS_PRINT("Got match for:\n    ");
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
}

#define MAX_SUB      4
#define MAX_TOPICS   4
#define MAX_FORMATS  7

static const char* formats[MAX_FORMATS] = {
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/*/%d/%d",
    "%d/*",
    "*/%d",
    "%d/*/%d"
};

static void OnTimer(uv_timer_t* handle)
{
    static DPS_Subscription* subscriptions[MAX_SUB];
    char* topics[MAX_TOPICS];
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_Status ret;
    int sub;
    int numTopics;
    int i;

    /*
     * Randomly choose a subscription - if the subscription is in use cancel it, otherwise create a new one.
     */
    sub = rand() % MAX_SUB;
    if (subscriptions[sub]) {
        ret = DPS_SubscribeCancel(node, subscriptions[sub]);
        subscriptions[sub] = NULL;
        return;
    }
    /*
     * Build a random set of topics
     */
    numTopics = 1 + (rand() % (MAX_TOPICS - 1));
    for (i = 0; i < numTopics; ++i) {
        const char* fmt = formats[rand() % MAX_FORMATS];
        int a = rand() % 4;
        int b = rand() % 4;
        int c = rand() % 4;
        int d = rand() % 4;
        topics[i] = malloc(32);
        sprintf(topics[i], fmt, a, b, c, d);
    }

    ret = DPS_Subscribe(node, topics, numTopics, OnPubMatch, &subscriptions[sub]);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
    }
    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
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
    char** arg = ++argv;
    DPS_Node* node;
    DPS_NodeAddress addr;
    uv_loop_t* loop;
    uv_idle_t idler;
    uv_timer_t timer;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = NULL;
    int listenPort = 0;
    const char* connectPort = NULL;

    DPS_Debug = 0;

    while (--argc) {
        if (strcmp(*arg, "-p") == 0) {
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            connectPort = *arg++;
            continue;
        }
        if (strcmp(*arg, "-l") == 0) {
            char* p;

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
            mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
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

    uv_timer_init(loop, &timer);
    timer.data = node;
    uv_timer_start(&timer, OnTimer, 1000, 10000);

    return uv_run(loop, UV_RUN_DEFAULT);

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-a <hostname>] [-l <listen port] [-m] [-d]\n", *argv);
    return 1;
}
