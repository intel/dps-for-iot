/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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

#include <set>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include <dps/Node.hpp>
#include <dps/Subscriber.hpp>
#include <dps/SubscriberListener.hpp>

class NodeListener : public dps::NodeListener
{
public:
    virtual ~NodeListener() { }
    virtual void onNewChange(dps::Node * node, const dps::RemoteNode * remote) {
        DPS_PRINT("onNewChange\n");
    }
};

class SubscriberListener : public dps::SubscriberListener
{
public:
  virtual ~SubscriberListener() { }
  virtual void onNewPublication(dps::Subscriber * subscriber) {
      DPS_PRINT("CACHE count=%d\n", subscriber->unreadCount());
  }
};

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    DPS_Event* event = (DPS_Event*)data;
    DPS_SignalEvent(event, DPS_OK);
}

static DPS_Status DestroyNode(DPS_Node* node)
{
    DPS_Event* event = nullptr;
    DPS_Status ret;

    if (!node) {
        return DPS_OK;
    }

    event = DPS_CreateEvent();
    if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_DestroyNode(node, OnNodeDestroyed, event);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = DPS_WaitForEvent(event);

Exit:
    DPS_DestroyEvent(event);
    return ret;
}

#define MAX_ARGS 32

static void Trim(char* s, size_t n)
{
    size_t len = strnlen(s, n);
    while (len && isspace(s[len - 1])) {
        --len;
    }
    s[len] = 0;
}

static int Parse(char* s, size_t n, char** argv)
{
    int argc = 0;
    char* tok;
    Trim(s, n);
    for (tok = strtok(s, " "); tok && (argc < MAX_ARGS); tok = strtok(nullptr, " ")) {
        argv[argc++] = tok;
    }
    return argc;
}

static int IntArg(const char* opt, char*** argp, int* argcp, int* val, int min, int max)
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

static void ReadStdin(dps::Node* node, NodeListener * listener, dps::Subscriber* subscriber)
{
    char lineBuf[256];
    int argc;
    char *argv[MAX_ARGS];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != nullptr) {
        argc = Parse(lineBuf, sizeof(lineBuf), argv);
        if (!argc) {
            continue;
        }
        if (!strcmp(argv[0], "take")) {
            dps::RxStream buf;
            dps::PublicationInfo info;
            if (!subscriber->takeNextData(buf, info)) {
                continue;
            }
            std::string msg;
            buf >> msg;
            DPS_PRINT("%s(%d) %s\n", DPS_UUIDToString(&info.uuid), info.sn, msg.c_str());
        } else if (!strcmp(argv[0], "ack")) {
            dps::RxStream rxBuf;
            dps::PublicationInfo info;
            if (!subscriber->takeNextData(rxBuf, info)) {
                continue;
            }
            std::string msg;
            rxBuf >> msg;
            DPS_PRINT("%s(%d) %s\n", DPS_UUIDToString(&info.uuid), info.sn, msg.c_str());
            dps::TxStream txBuf;
            txBuf << std::string("goodbye");
            DPS_Status ret = subscriber->ack(std::move(txBuf), &info.uuid, info.sn);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("ack failed: %s\n", DPS_ErrTxt(ret));
            }
        } else if (!strcmp(argv[0], "dump")) {
            subscriber->dump();
        } else if (!strcmp(argv[0], "adv")) {
            node->advertise();
        } else if (!strcmp(argv[0], "names")) {
            std::vector<const dps::RemoteNode*> remotes = node->discovered();
            for (auto remote = remotes.begin(); remote != remotes.end(); ++remote) {
                DPS_PRINT("name=%s,namespace=%s\n", (*remote)->name_, (*remote)->namespace_);
            }
        } else if (!strcmp(argv[0], "pubs") && (1 < argc)) {
            DPS_PRINT("%d\n", node->publisherCount(argv[1]));
        } else if (!strcmp(argv[0], "subs") && (1 < argc)) {
            DPS_PRINT("%d\n", node->subscriberCount(argv[1]));
        }
    }
}

#define MAX_LINKS  8

int main(int argc, char** argv)
{
    std::vector<std::string> topics = { "A" };
    char** arg = argv + 1;
    int listenPort = 0;
    const char* host = NULL;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int numLinks = 0;
    DPS_NodeAddress* addr = nullptr;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    NodeListener* nodeListener = nullptr;
    dps::Node* node = nullptr;
    dps::QoS qos = { 4, dps::DPS_QOS_VOLATILE, dps::DPS_QOS_BEST_EFFORT };
    int depth;
    int durability;
    int reliability;
    bool isService = false;
    dps::SubscriberListener* listener = nullptr;
    dps::Subscriber* subscriber = nullptr;
    size_t i;
    DPS_Status ret;

    DPS_Debug = DPS_FALSE;
    while (--argc) {
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = DPS_TRUE;
            continue;
        }
        if (IntArg("-l", &arg, &argc, &listenPort, 1, UINT16_MAX)) {
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
        if (IntArg("-p", &arg, &argc, &linkPort[numLinks], 1, UINT16_MAX)) {
            linkHosts[numLinks] = host;
            ++numLinks;
            continue;
        }
        if (IntArg("--depth", &arg, &argc, &depth, 1, 1000)) {
            qos.depth = depth;
            continue;
        }
        if (IntArg("--durability", &arg, &argc, &durability, dps::DPS_QOS_VOLATILE, dps::DPS_QOS_TRANSIENT)) {
            qos.durability = (dps::QoSDurability)durability;
            continue;
        }
        if (IntArg("--reliability", &arg, &argc, &reliability, dps::DPS_QOS_BEST_EFFORT, dps::DPS_QOS_RELIABLE)) {
            qos.reliability = (dps::QoSReliability)reliability;
            continue;
        }
        if (strcmp(*arg, "-s") == 0) {
            ++arg;
            isService = true;
            continue;
        }
    }
    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (listenPort || numLinks) {
        mcast = DPS_MCAST_PUB_DISABLED;
        addr = DPS_CreateAddress();
    }

    nodeListener = new NodeListener();
    node = new dps::Node(0, "sub_qos", nodeListener);
    ret = node->initialize(mcast, listenPort);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(node->get()));

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node->get(), linkHosts[i], linkPort[i], addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Subscriber is linked to %s\n", DPS_NodeAddrToString(addr));
        } else {
            DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
        }
    }

    listener = new SubscriberListener();
    if (qos.reliability == dps::DPS_QOS_BEST_EFFORT) {
        subscriber = new dps::Subscriber(qos, listener);
    } else {
        subscriber = new dps::ReliableSubscriber(qos, listener);
    }
    ret = subscriber->initialize(node, topics);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    subscriber->setDiscoverable(true);

    ReadStdin(node, nodeListener, subscriber);

    ret = subscriber->close();
    if (ret != DPS_OK) {
        return ret;
    }
    delete subscriber;
    delete listener;
    ret = node->close();
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    delete node;
    delete nodeListener;
    DPS_DestroyAddress(addr);
    return EXIT_SUCCESS;

Usage:
    DPS_PRINT("Usage: %s\n", argv[0]);
    return EXIT_FAILURE;
}
