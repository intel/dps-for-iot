#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <dps_dbg.h>
#include <bitvec.h>
#include <dps.h>
#include <uv.h>

#define MAX_TOPICS 64

static char* topics[MAX_TOPICS];
static size_t numTopics = 0;

static int requestAck = DPS_FALSE;

static DPS_Publication* currentPub = NULL;

static int AddTopics(char* topicList, char** msg, int* keep, int* ttl)
{
    size_t i;

    for (i = 0; i < numTopics; ++i) {
        free(topics[i]);
    }
    *msg = NULL;
    *keep = 0;
    *ttl = 0;
    numTopics = 0;
    while (numTopics < MAX_TOPICS) {
        size_t len = strcspn(topicList, " ");
        if (!len) {
            len = strlen(topicList);
        }
        if (topicList[0] == '-') {
            switch(topicList[1]) {
            case 't':
                if (!sscanf(topicList, "-t %d", ttl)) {
                    return 0;
                }
                topicList += 3;
                break;
            case 'm':
                /*
                 * After "-m" the rest of the line is a message
                 */
                *msg = topicList + 1 + len;
                return 1;
            case 'k':
                *keep = 1;
                break;

            }
            len = strcspn(topicList, " ");
            if (!len) {
                return 0;
            }
        } else {
            topics[numTopics] = malloc(len + 1);
            memcpy(topics[numTopics], topicList, len);
            topics[numTopics][len] = 0;
            ++numTopics;
            if (!topicList[len]) {
                break;
            }
        }
        topicList += len + 1;
    }
    return 1;
}

static void OnAck(DPS_Node* node, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_PRINT("Ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(node, pub)), DPS_PublicationGetSerialNumber(node, pub));
    if (len) {
        DPS_PRINT("    %.*s\n", len, data);
    }
}

static void ReadStdin(DPS_Node* node)
{
    void* data;
    char lineBuf[200];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != NULL) {
        size_t len = strlen(lineBuf);
        int ttl;
        int keep;
        char* msg;
        DPS_Status ret;

        while (len && isspace(lineBuf[len - 1])) {
            --len;
        }
        if (!len) {
            continue;
        }
        lineBuf[len] = 0;

        DPS_PRINT("Pub: %s\n", lineBuf);

        if (!AddTopics(lineBuf, &msg, &keep, &ttl)) {
            DPS_PRINT("Invalid\n");
            return;
        }
        if (!currentPub) {
            keep = 0;
        }
        if (!keep) {
            DPS_DestroyPublication(node, currentPub, &data);
            ret = DPS_CreatePublication(node, topics, numTopics, requestAck ? OnAck : NULL, &currentPub);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
                return;
            }
        }
        ret = DPS_Publish(node, currentPub, msg, msg ? strlen(msg) : 0, ttl, NULL);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(node, currentPub)), DPS_PublicationGetSerialNumber(node, currentPub));
        } else {
            DPS_ERRPRINT("Failed to publish %s error=%s\n", lineBuf, DPS_ErrTxt(ret));
        }
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
    int wait = DPS_FALSE;
    int ttl = 0;
    char* msg = NULL;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-n", &arg, &argc, &numHashes, 2, 16)) {
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
        if (strcmp(*arg, "-h") == 0) {
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
        if (IntArg("-t", &arg, &argc, &ttl, 0, 2000)) {
            continue;
        }
        if (strcmp(*arg, "-w") == 0) {
            ++arg;
            wait = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            requestAck = DPS_TRUE;
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
    ret = DPS_Configure(bitLen, numHashes);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Invalid configuration parameters\n");
        goto Usage;
    }

    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (host || connectPort) {
        mcast = DPS_MCAST_PUB_DISABLED;
    }

    ret = DPS_CreateNode(&node, mcast, 0, "/.");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    if (host || connectPort) {
        ret = DPS_ResolveAddress(node, host, connectPort, &addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to resolve %s/%s\n", host ? host : "<localhost>", connectPort);
            return 1;
        }
        ret = DPS_Join(node, &addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_Join failed: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }

    if (numTopics) {
        ret = DPS_CreatePublication(node, topics, numTopics, NULL, &currentPub);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
            return 1;
        }
        ret = DPS_Publish(node, currentPub, msg, msg ? strlen(msg) + 1 : 0, ttl, NULL);
        if (ret == DPS_OK) {
            DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(node, currentPub)));
        } else {
            DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        }
        if (!wait) {
            DPS_StopNode(node);
        }
        DPS_DestroyNode(node);
    } else {
        DPS_PRINT("Running in interactive mode\n");
        ReadStdin(node);
    }
    return 0;

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-h <hostname>] [-d] [-m <message>] [topic1 topic2 ... topicN]\n", *argv);
    return 1;
}


