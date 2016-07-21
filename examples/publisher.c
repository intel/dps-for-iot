#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps_dbg.h>
#include <bitvec.h>
#include <dps.h>
#include <uv.h>

#define MAX_TOPICS 64

static char lineBuf[200];
static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static void OnAlloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = lineBuf;
    buf->len = sizeof(lineBuf);
}

static DPS_Publication* currentPub = NULL;

static void AddTopics(const char* topicList)
{
    size_t i;

    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
    }
    numTopics = 0;
    for (i = 0; i < MAX_TOPICS; ++i) {
        size_t len = strcspn(topicList, " ");
        if (!len) {
            len = strlen(topicList);
        }
        topics[i] = malloc(len + 1);
        memcpy(topics[i], topicList, len);
        topics[i][len] = 0;
        ++numTopics;
        if (!topicList[len]) {
            break;
        }
        topicList += len + 1;
    }
}

static void OnData(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    void* data;

    if (lineBuf[nread - 1] == '\n') {
        DPS_Status ret;
        DPS_Node* node = (DPS_Node*)stream->data;

        lineBuf[nread - 1] = 0;
        DPS_PRINT("Pub: %s\n", lineBuf);

        DPS_PublishCancel(node, currentPub, &data);
        AddTopics(lineBuf);
        ret = DPS_Publish(node, topics, numTopics, &currentPub, NULL, 0);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to publish %s error=%s\n", lineBuf, DPS_ErrTxt(ret));
        }
    }
}

#define STDIN 1

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
    int r;
    DPS_Status ret;
    DPS_Node* node;
    DPS_NodeAddress addr;
    char** arg = argv + 1;
    uv_loop_t* loop;
    uv_tty_t tty;
    const char* host = NULL;
    const char* connectPort = NULL;
    int bitLen = 16 * 1024;
    int numHashes = 4;
    char* msg = NULL;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-h", &arg, &argc, &numHashes, 2, 16)) {
            continue;
        }
        if (IntArg("-b", &arg, &argc, &bitLen, 64, 8 * 1024 * 1024)) {
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
            if (!--argc) {
                goto Usage;
            }
            msg = *arg++;
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
            DPS_PRINT("Too many topics - increase limit and recompile\n");
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }
    if (numTopics == 0) {
        DPS_PRINT("Need a least one topic to publish\n");
        return 1;
    }
    ret = DPS_Configure(bitLen, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    node = DPS_InitNode(DPS_FALSE, 0, "/.");
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

    ret = DPS_Publish(node, topics, numTopics, &currentPub, msg, msg ? strlen(msg) + 1 : 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
    }
    /*
     *  We don't want to try to free the argv strings
     */
    numTopics = 0;

    r = uv_tty_init(loop, &tty, STDIN, 1);
    assert(r == 0);
    tty.data = node;
    uv_read_start((uv_stream_t*)&tty, OnAlloc, OnData);
    return uv_run(loop, UV_RUN_DEFAULT);

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-a <hostname>] [-d] [-m <message>] topic1 topic2 ... topicN\n", *argv);
    return 1;
}


