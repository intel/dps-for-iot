#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <dps/dps_dbg.h>
#include <dps/bitvec.h>
#include <dps/dps.h>
#include <dps/dps_synchronous.h>
#include <dps/dps_event.h>

#define MAX_TOPICS 64

static int pubCount = 1;
static int ttl = 0;
static int quiet = DPS_FALSE;

static DPS_Event* nodeDestroyed;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_SignalEvent(nodeDestroyed, DPS_OK);
}

static void OnAck(DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Node* node = DPS_GetPublicationNode(pub);

    if (!quiet) {
        DPS_PRINT("Ack for pub UUID %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), DPS_PublicationGetSequenceNum(pub));
        if (len) {
            DPS_PRINT("    %.*s\n", (int)len, data);
        }
    }
    if (--pubCount) {
        DPS_Status ret = DPS_Publish(pub, NULL, 0, ttl, NULL);
        if (ret == DPS_OK) {
            return;
        }
        DPS_ERRPRINT("Failed to publish: %s\n", DPS_ErrTxt(ret));
    }
    DPS_DestroyPublication(pub, NULL);
    DPS_DestroyNode(node, OnNodeDestroyed, NULL);
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
    const char* topics[MAX_TOPICS];
    size_t numTopics = 0;
    DPS_Publication* pub = NULL;
    DPS_Node* node;
    char** arg = argv + 1;
    const char* host = NULL;
    int linkPort = 0;
    char* msg = NULL;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND;
    DPS_NodeAddress* addr = NULL;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-p", &arg, &argc, &linkPort, 1, UINT16_MAX)) {
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
        if (IntArg("-c", &arg, &argc, &pubCount, 1, INT32_MAX)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (strcmp(*arg, "-q") == 0) {
            ++arg;
            quiet = DPS_TRUE;
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
    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (linkPort) {
        mcast = DPS_MCAST_PUB_DISABLED;
    }

    node = DPS_CreateNode("/.");
    ret = DPS_StartNode(node, mcast, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    if (linkPort) {
        addr = DPS_CreateAddress();
        ret = DPS_LinkTo(node, host, linkPort, addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_LinkTo returned %s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }

    pub = DPS_CreatePublication(node);
    ret = DPS_InitPublication(pub, topics, numTopics, DPS_FALSE, OnAck);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to create publication - error=%d\n", ret);
        return 1;
    }

    nodeDestroyed = DPS_CreateEvent();

    ret = DPS_Publish(pub, msg, msg ? strlen(msg) + 1 : 0, ttl, NULL);
    if (ret == DPS_OK) {
        DPS_PRINT("Pub UUID %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)));
    } else {
        DPS_ERRPRINT("Failed to publish topics - error=%d\n", ret);
        DPS_DestroyPublication(pub, NULL);
        DPS_DestroyNode(node, OnNodeDestroyed, NULL);
    }

    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);

    return 0;

Usage:
    DPS_PRINT("Usage %s [-d] [-p <port>] [-h <host>] [-m <message>] [-t <ttl>] [-c <count>] [topic1 topic2 ... topicN]\n", *argv);
    return 1;
}


