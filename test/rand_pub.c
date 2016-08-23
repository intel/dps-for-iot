#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <dps.h>
#include <uv.h>

static char lineBuf[200];

#define MAX_TOPICS   100
#define MAX_FORMATS    5

static const char* formats[MAX_FORMATS] = {
    "%d",
    "%d/%d",
    "%d/%d/%d",
    "%d/%d/%d/%d",
    "%d/%d/%d/%d/%d"
};

static void OnTimer(uv_timer_t* handle)
{
    static DPS_Publication* currentPub = NULL;
    static char* randTopics[MAX_TOPICS];
    char* topics[MAX_TOPICS];
    size_t numTopics = 0;
    DPS_Node* node = (DPS_Node*)handle->data;
    DPS_Status ret;
    size_t i;
    int pub;

    /*
     * Randomly choose a topic to remove
     */
    pub = rand() % MAX_TOPICS;
    if (randTopics[pub]) {
        free(randTopics[pub]);
        randTopics[pub] = NULL;
    } else {
        /*
         * Build a random topic
         */
        const char* fmt = formats[rand() % MAX_FORMATS];
        int a = rand() % 4;
        int b = rand() % 4;
        int c = rand() % 4;
        int d = rand() % 4;
        int e = rand() % 4;
        randTopics[pub] = malloc(32);
        sprintf(randTopics[pub], fmt, a, b, c, d, e);
    }
    /*
     * Pack topics
     */
    DPS_PRINT("Publishing:\n");
    for (i = 0; i < MAX_TOPICS; ++i) {
        if (randTopics[i]) {
            topics[numTopics++] = randTopics[i];
            DPS_PRINT("  %s\n", randTopics[i]);
        }
    }
    if (currentPub) {
        void* data;
        ret = DPS_DestroyPublication(node, currentPub, &data);
    }
    ret = DPS_CreatePublication(node, topics, numTopics, NULL, &currentPub);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
        return;
    }
    ret = DPS_Publish(node, currentPub, NULL, 0, 0, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to publish topics - error=%s\n", DPS_ErrTxt(ret));
    }
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    DPS_Node* node;
    char** arg = ++argv;
    uv_loop_t* loop;
    int portNum = 0;
    uv_timer_t timer;

    DPS_Debug = 0;

    while (--argc) {
        if (strcmp(*arg, "-p") == 0) {
            char* p;
            ++arg;
            if (!--argc) {
                goto Usage;
            }
            portNum = strtol(*arg++, &p, 10); 
            if (*p) {
                DPS_PRINT("Port number (-p) option requires a decimal number\n");
                goto Usage;
            }
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        goto Usage;
    }

    DPS_CreateNode(&node, DPS_MCAST_PUB_ENABLE_SEND, portNum, "/.");
    assert(node);

    loop = DPS_GetLoop(node);
    uv_timer_init(loop, &timer);
    timer.data = node;
    uv_timer_start(&timer, OnTimer, 1000, 10);

    DPS_DestroyNode(node);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-d]\n", *argv);
    return 1;
}


