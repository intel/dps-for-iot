#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps/dps_dbg.h>
#include <dps/network.h>
#include <dps/dps.h>
#include <dps/dps_synchronous.h>

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    static DPS_Subscription* prev;
    static int count;

    if (sub == prev) {
        ++count;
    } else {
        size_t i;
        size_t numTopics = DPS_SubscriptionGetNumTopics(sub);

        if (count > 1) {
            DPS_PRINT("and another %d matches\n", count);
        }
        count = 0;
        prev = sub;

        DPS_PRINT("Got match for:\n    ");
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
}

#define MAX_SUB      4
#define MAX_TOPICS   4
#define MAX_FORMATS  7

static const char* formats[MAX_FORMATS] = {
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/+/%d/%d",
    "%d/#",
    "+/%d",
    "%d/+/%d"
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
        ret = DPS_DestroySubscription(subscriptions[sub]);
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

    subscriptions[sub] = DPS_CreateSubscription(node, topics, numTopics);
    ret = DPS_Subscribe(subscriptions[sub], OnPubMatch);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
    }
    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
    }
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
    char** arg = ++argv;
    DPS_Node* node;
    uv_loop_t* loop;
    uv_idle_t idler;
    uv_timer_t timer;
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = NULL;
    int listenPort = 0;
    int linkPort = 0;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-p", &arg, &argc, &linkPort, 1, UINT16_MAX)) {
            continue;
        }
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
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

    if (!linkPort) {
        mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
    }

    node = DPS_CreateNode("/.");
    ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to initialize node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    if (linkPort) {
        DPS_NodeAddress* addr = DPS_CreateAddress(addr);
        ret = DPS_LinkTo(node, host, linkPort, addr);
        DPS_DestroyAddress(addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_LinkTo returned %s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }

    loop = DPS_GetLoop(node);
    uv_timer_init(loop, &timer);
    timer.data = node;
    uv_timer_start(&timer, OnTimer, 1000, 10000);

    DPS_DestroyNode(node);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-a <hostname>] [-l <listen port] [-m] [-d]\n", *argv);
    return 1;
}
