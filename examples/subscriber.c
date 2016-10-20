#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps/dps_dbg.h>
#include <dps/dps.h>
#include <dps/dps_synchronous.h>
#include <dps/dps_event.h>

static int quiet = DPS_FALSE;
static int sendAck = DPS_FALSE;

static uint8_t AckMsg[] = "This is an ACK";

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t i;
    size_t numTopics;

    if (!quiet) {
        DPS_PRINT("Pub %s(%d) matches:\n", DPS_UUIDToString(pubId), sn);
        DPS_PRINT("  pub ");
        numTopics = DPS_PublicationGetNumTopics(pub);
        for (i = 0; i < numTopics; ++i) {
            if (i) {
                DPS_PRINT(" | ");
            }
            DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
        }
        DPS_PRINT("\n");
        DPS_PRINT("  sub ");
        numTopics = DPS_SubscriptionGetNumTopics(sub);
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
    char* topicList[64];
    char** arg = ++argv;
    int numTopics = 0;
    DPS_Node* node;
    DPS_Event* nodeDestroyed;
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
        if (strcmp(*arg, "-s") == 0) {
            ++arg;
            /*
             * NULL separator between topic lists
             */
            if (numTopics > 0) {
                topicList[numTopics++] = NULL;
            }
            continue;
        }
        if (*arg[0] == '-') {
            goto Usage;
        }
        if (numTopics == A_SIZEOF(topicList)) {
            DPS_PRINT("%s: Too many topics - increase limit and recompile\n", *argv);
            goto Usage;
        }
        topicList[numTopics++] = *arg++;
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

    nodeDestroyed = DPS_CreateEvent();

    if (numTopics > 0) {
        char** topics = topicList;
        while (numTopics >= 0) {
            DPS_Subscription* subscription;
            int count = 0;
            while (count < numTopics) {
                if (!topics[count]) {
                    break;
                }
                ++count;
            }
            subscription = DPS_CreateSubscription(node, (const char**)topics, count);
            ret = DPS_Subscribe(subscription, OnPubMatch);
            if (ret != DPS_OK) {
                break;
            }
            topics += count + 1;
            numTopics -= count + 1;
        }
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
            DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
            DPS_WaitForEvent(nodeDestroyed);
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
            DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
            DPS_WaitForEvent(nodeDestroyed);
            return 1;
        }
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-p <portnum>] [-h <hostname>] [-l <listen port] [-m] [-d] [-s topic1 ... topicN]\n", *argv);
    return 1;
}
