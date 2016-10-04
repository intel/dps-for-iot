#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dps/dps_dbg.h>
#include <dps/network.h>
#include <dps/dps.h>
#include <dps/dps_synchronous.h>
#include <dps/dps_registration.h>
#include <dps/bitvec.h>
#include <uv.h>

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_AckPublication(pub, NULL, 0);
    if (ret != DPS_OK) {
        DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
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
    const char* topics[1];
    DPS_Subscription* subscription;
    int listenPort = 30000;

    DPS_Debug = 0;

    while (--argc) {
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
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

    node = DPS_CreateNode("/");
    ret = DPS_StartNode(node, 0, listenPort);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_PRINT("Registration services is listening on port %d\n", DPS_GetPortNumber(node));

    topics[0] = DPS_RegistryTopicString;
    subscription = DPS_CreateSubscription(node, topics, 1);
    ret = DPS_Subscribe(subscription, OnPubMatch);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to susbscribe topics - error=%s\n", DPS_ErrTxt(ret));
        return 1;
    }
    DPS_DestroyNode(node);
    return 0;

Usage:
    DPS_PRINT("Usage %s [-l <listen port] [-d]\n", *argv);
    return 1;
}
