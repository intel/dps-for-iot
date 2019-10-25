/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#include "test.h"
#include "node.h"
#include "keys.h"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define DESCRIBE(n)  DPS_NodeAddrToString(&(n)->ep.addr)

typedef struct _Args {
    int wait;     /* how long to wait for a link to come up */
    int delay;    /* how long to go unresponsive after breaking a link */
    int repeats;  /* how many times to run the test */
} Args;

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_SignalEvent((DPS_Event*)data, DPS_OK);
    }
}

static void OnUnlink(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
    DPS_PRINT("Clean unlink from remote node %s\n", DPS_NodeAddrToString(addr));
    DPS_DestroyNode(node, OnNodeDestroyed, (DPS_Event*)data);
}

static RemoteNode* WaitForActiveRemote(DPS_Node* node, int timeout)
{
    timeout *= 1000;
    while (timeout > 0) {
        RemoteNode* remote;
        DPS_LockNode(node);
        for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
            if (remote->state == REMOTE_ACTIVE) {
                DPS_UnlockNode(node);
                /* Allow time for link to complete */
                SLEEP(100);
                DPS_PRINT("Linked to remote %s\n", DESCRIBE(remote));
                return remote;
            }
        }
        DPS_UnlockNode(node);
        SLEEP(10);
        timeout -= 10;
    }
    return NULL;
}

static DPS_Status BreakLink(DPS_Node* node, int timeout, int delay)
{
    DPS_Status ret = DPS_OK;
    RemoteNode* remote = WaitForActiveRemote(node, timeout);
    if (!remote) {
        return DPS_ERR_TIMEOUT;
    }
    DPS_LockNode(node);
    DPS_PRINT("Deleting remote node %s\n", DESCRIBE(remote));
    DPS_DeleteRemoteNode(node, remote);
    DPS_PRINT("Node going unresponsive for %d seconds\n", delay);
    node->state = DPS_NODE_PAUSED;
    delay *= 1000;
    while (delay > 0) {
        DPS_UnlockNode(node);
        SLEEP(10);
        delay -= 10;
        DPS_LockNode(node);
        if (node->state != DPS_NODE_PAUSED) {
            ret = DPS_ERR_FAILURE;
            break;
        }
    }
    if (node->state == DPS_NODE_PAUSED) {
        node->state = DPS_NODE_RUNNING;
    }
    DPS_UnlockNode(node);
    return ret;
}

static int ParseArgs(int argc, char** argv, Args* args)
{
    memset(args, 0, sizeof(Args));
    args->wait = 5;
    args->delay = 5;
    args->repeats = 4;

    for (; argc; --argc) {
        if (IntArg("-t", &argv, &argc, &args->delay, 0, 500)) {
            continue;
        }
        if (IntArg("-w", &argv, &argc, &args->wait, 0, 500)) {
            continue;
        }
        if (IntArg("-r", &argv, &argc, &args->repeats, 0, 100)) {
            continue;
        }
        if (strcmp(*argv, "-d") == 0) {
            ++argv;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (*argv[0] == '-') {
            return DPS_FALSE;
        }
    }
    return DPS_TRUE;
}

static DPS_MemoryKeyStore* CreateKeyStore(void)
{
    DPS_MemoryKeyStore* keyStore;
    size_t i;
    const Id* id;

    keyStore = DPS_CreateMemoryKeyStore();
    DPS_SetNetworkKey(keyStore, &NetworkKeyId, &NetworkKey);
    for (i = 0; i < NUM_KEYS; ++i) {
        DPS_SetContentKey(keyStore, &PskId[i], &Psk[i]);
    }
    DPS_SetTrustedCA(keyStore, TrustedCAs);
    for (id = Ids; id->keyId.id; ++id) {
        DPS_SetCertificate(keyStore, id->cert, id->privateKey, id->password);
    }
    return keyStore;
}

int main(int argc, char** argv)
{
    DPS_Status ret;
    Args args;
    DPS_MemoryKeyStore* keyStore = NULL;
    DPS_Node* node;
    DPS_Event* nodeDestroyed = NULL;
    RemoteNode* remote;

    DPS_Debug = DPS_FALSE;

    if (!ParseArgs(argc - 1, argv + 1, &args)) {
        goto Usage;
    }

    keyStore = CreateKeyStore();
    ASSERT(keyStore);
    node = DPS_CreateNode("/.", DPS_MemoryKeyStoreHandle(keyStore), NULL);
    ASSERT(node);

    nodeDestroyed = DPS_CreateEvent();

    ret = DPS_StartNode(node, 0, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_PRINT("Link Dropper is listening on %s\n", DPS_GetListenAddressString(node));

    /*
     * Wait until there is a link up and then break it
     */
    ret = BreakLink(node, 120, args.delay);
    if (ret == DPS_OK) {
        while (args.repeats) {
            ret = BreakLink(node, args.wait, args.delay);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Failed to get recovered link %s\n", DPS_ErrTxt(ret));
                goto Exit;
            }
            --args.repeats;
        }
    } else {
        DPS_ERRPRINT("Timed out waiting for initial link\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    /*
     * Wait until the link is back up
     */
    remote = WaitForActiveRemote(node, args.wait);
    if (!remote) {
        ret = DPS_ERR_TIMEOUT;
        DPS_ERRPRINT("Failed to get recovered link %s\n", DPS_ErrTxt(ret));
        goto Exit;
    }
    DPS_LockNode(node);
    DPS_Unlink(node, &remote->ep.addr, OnUnlink, nodeDestroyed);
    DPS_UnlockNode(node);

Exit:

    if (ret != DPS_OK) {
        DPS_DestroyNode(node, OnNodeDestroyed, nodeDestroyed);
    }
    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);
    DPS_DestroyMemoryKeyStore(keyStore);
    return (ret == DPS_OK) ? EXIT_SUCCESS : EXIT_FAILURE;

Usage:
    DPS_PRINT("Usage %s [-d] [-w <seconds>] [-r <count>]\n", argv[0]);
    DPS_PRINT("       -d: Enable debug ouput if built for debug.\n");
    DPS_PRINT("       -w: Time to wait in seconds for a link to be restored\n");
    DPS_PRINT("       -t: Time to go unresponsive after dropping a link\n");
    DPS_PRINT("       -r: Number of times to repeat test case.\n");
    return EXIT_FAILURE;
}
