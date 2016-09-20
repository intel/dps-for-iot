#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps/dps_dbg.h>
#include <dps/network.h>
#include <dps/dps.h>
#include <dps/dps_synchronous.h>
#include <dps/bitvec.h>
#include <uv.h>

static int quiet = DPS_FALSE;
static int sendAck = DPS_FALSE;

static uint8_t AckMsg[] = "This is an ACK";

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t i;
    size_t numTopics = DPS_SubscriptionGetNumTopics(sub);

    if (!quiet) {
        DPS_PRINT("Pub %s(%d) matches:\n    ", DPS_UUIDToString(pubId), sn);
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
    if (sendAck) {
        DPS_Status ret = DPS_AckPublication(pub, AckMsg, sizeof(AckMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

#if 0
static void ReadStdin()
{
    char lineBuf[200];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != NULL) {
        if (lineBuf[0] == 'q') {
            exit(0);
        }
    }
}
#endif

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
    int mcastPub = DPS_MCAST_PUB_DISABLED;
    const char* host = NULL;
    int listenPort = 0;
    int linkPort = 0;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
            continue;
        }
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
        if (strcmp(*arg, "-q") == 0) {
            ++arg;
            quiet = DPS_TRUE;
            continue;
        }
        if (strcmp(*arg, "-a") == 0) {
            ++arg;
            sendAck = DPS_TRUE;
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
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topics)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topics[numTopics++] = *arg++;
    }

    if (!linkPort) {
        mcastPub = DPS_MCAST_PUB_ENABLE_RECV;
    }

    node = DPS_CreateNode("/.");
    ret = DPS_StartNode(node, mcastPub, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(node));

    if (numTopics > 0) {
        DPS_Subscription* subscription = DPS_CreateSubscription(node, topics, numTopics);
        ret = DPS_Subscribe(subscription, OnPubMatch);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }
    if (linkPort) {
        DPS_NodeAddress* addr = DPS_CreateAddress();
        DPS_Status linkRet = DPS_ERR_FAILURE;
        ret = DPS_LinkTo(node, host, linkPort, addr);
        DPS_DestroyAddress(addr);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("DPS_LinkTo returned %s\n", DPS_ErrTxt(ret));
            return 1;
        }
    }
    DPS_DestroyNode(node);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-h <hostname>] [-l <listen port] [-m] [-d] topic1 topic2 ... topicN\n", *argv);
    return 1;
}
