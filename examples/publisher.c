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

int main(int argc, char** argv)
{
    int r;
    DPS_Status ret;
    DPS_Node* node;
    char** arg = argv + 1;
    uv_loop_t* loop;
    uv_tty_t tty;
    int portNum = 0;
    size_t filterBits = 0;
    size_t numHashes = 4;
    char* msg = NULL;

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
            portNum = strtol(*arg++, &p, 10); 
            if (*p) {
                DPS_PRINT("Port number (-p) option requires a decimal number\n");
                goto Usage;
            }
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

    if (filterBits) {
        ret = DPS_Configure(filterBits, numHashes);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Invalid configuration parameters\n");
            goto Usage;
        }
    }

    node = DPS_InitNode(DPS_FALSE, portNum, "/.");
    assert(node);
    loop = DPS_GetLoop(node);

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
    DPS_PRINT("Usage %s [-p <portnum>] [-d] [-m <message>] topic1 topic2 ... topicN\n", *argv);
    return 1;
}


