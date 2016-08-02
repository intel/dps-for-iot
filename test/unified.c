#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <bitvec.h>
#include <dps.h>
#include <uv.h>

#define MAX_TOPICS 64


#define BASE_PORT_NUM 35000


static char* subTopics[] = { "1/2/3" };
static char* pubTopics[] = { "1/2/3" };

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

static void OnMatch(DPS_Node* node, DPS_Subscription* subscription, const char** topics, size_t numTopics, uint8_t* data, size_t len)
{
    size_t i;

    DPS_PRINT("Got match for:\n    ");
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

static DPS_Node** pubNode;
static DPS_Publication** publications;
static int numPubs = 1;

static void OnTimer(uv_timer_t* handle)
{
    static int pubcount = 0;
    size_t p;
    DPS_Status ret;

    DPS_PRINT("***** Publish some topics\n");

    /*
     * Publish some topics
     */
    for (p = 0; p < numPubs; ++p) {
        void* data;
        char* msg;

        if (publications[p]) {
            void* data;
            DPS_DestroyPublication(pubNode[p], publications[p], &data);
            free(data);
        }
        msg = malloc(32);
        sprintf(msg, "publication #%d", ++pubcount);

        ret = DPS_CreatePublication(pubNode[p], pubTopics, 1, &publications[p]);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
            return;
        }
        ret = DPS_Publish(pubNode[p], publications[p], msg, strlen(msg), 0, NULL);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        }
    }
}

int main(int argc, char** argv)
{
    int r;
    DPS_Status ret;
    DPS_Node** subNode;
    char** arg = argv + 1;
    uv_timer_t timer;
    uv_loop_t* loop;
    int bitLen = 16 * 1024;
    int numHashes = 4;
    int numSubs = 1;
    size_t s;
    size_t p;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-h", &arg, &argc, &numHashes, 2, 16)) {
            continue;
        }
        if (IntArg("-b", &arg, &argc, &bitLen, 64, 8 * 1024 * 1024)) {
            continue;
        }
        if (IntArg("-p", &arg, &argc, &numPubs, 1, 100)) {
            continue;
        }
        if (IntArg("-s", &arg, &argc, &numSubs, 1, 100)) {
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
    }
    ret = DPS_Configure(bitLen, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }
    subNode = malloc(numSubs * sizeof(DPS_Node*));
    pubNode = malloc(numPubs * sizeof(DPS_Node*));
    publications = calloc(1, numPubs * sizeof(DPS_Publication*));

    loop = uv_default_loop();

    for (s = 0; s < numSubs; ++s) {
        subNode[s] = DPS_InitNode(DPS_FALSE, 0, "/.");
        assert(subNode[s]);
    }
    for (p = 0; p < numPubs; ++p) {
        pubNode[p] = DPS_InitNode(DPS_FALSE, BASE_PORT_NUM + p, "/.");
        assert(pubNode[p]);
    }

    DPS_PRINT("***** Join subscribers to publishers\n");

    /*
     * Join each subscriber to all publishers
     */
    for (p = 0; p < numPubs; ++p) {
        DPS_NodeAddress addr;
        char port[16];
        sprintf(port, "%d", BASE_PORT_NUM + p);
        for (s = 0; s < numSubs; ++s) {
            ret = DPS_ResolveAddress(subNode[s], NULL, port, &addr);
            assert(ret == DPS_OK);
            ret = DPS_Join(subNode[s], &addr);
            assert(ret == DPS_OK);
        }
    }

    DPS_PRINT("***** Register subscriptions\n");

    /*
     * Subscribe to some topics
     */
    for (s = 0; s < numSubs; ++s) {
        DPS_Subscription* subscription;
        ret = DPS_Subscribe(subNode[s], subTopics, 1, OnMatch, &subscription);
        if (ret != DPS_OK)  {
            DPS_ERRPRINT("Failed to susbscribe to topics - error=%s\n", DPS_ErrTxt(ret));
        }
    }

    uv_timer_init(loop, &timer);
    uv_timer_start(&timer, OnTimer, 1000, 2000);


    DPS_PRINT("***** Up and running\n");

    uv_run(loop, UV_RUN_DEFAULT);

    return 0;

Usage:
    DPS_PRINT("Usage %s [-d]\n", *argv);
    return 1;
}


