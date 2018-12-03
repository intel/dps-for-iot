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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include <dps/CborStream.hpp>
#include <dps/Publisher.hpp>

class PublisherListener : public dps::PublisherListener
{
public:
  virtual ~PublisherListener() { }
  virtual void onNewAcknowledgement(dps::Publisher * publisher) {
      DPS_PRINT("ACK count=%d\n", publisher->unreadCount());
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

static void ReadStdin(dps::Publisher* publisher)
{
    char lineBuf[256];
    int argc;
    char *argv[MAX_ARGS];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != nullptr) {
        argc = Parse(lineBuf, sizeof(lineBuf), argv);
        if (!argc) {
            continue;
        }
        if (!strcmp(argv[0], "pub")) {
            dps::TxStream buf;
            buf << std::string("hello");
            DPS_Status ret = publisher->publish(std::move(buf));
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
            }
        } else if (!strcmp(argv[0], "take")) {
            dps::RxStream rxBuf;
            dps::PublicationInfo info;
            if (!publisher->takeNextData(rxBuf, info)) {
                continue;
            }
            std::string msg;
            rxBuf >> msg;
            DPS_PRINT("%s(%d) %s\n", DPS_UUIDToString(&info.uuid), info.sn, msg.c_str());
        } else if (!strcmp(argv[0], "dump")) {
            publisher->dump();
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
    DPS_Node* node = nullptr;
    dps::QoS qos = { 4, dps::DPS_QOS_VOLATILE, dps::DPS_QOS_BEST_EFFORT };
    int depth;
    int durability;
    int reliability;
    bool isClient = false;
    dps::PublisherListener* listener = nullptr;
    dps::Publisher* publisher = nullptr;
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
        if (strcmp(*arg, "-c") == 0) {
            ++arg;
            isClient = true;
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

    node = DPS_CreateNode(nullptr, nullptr, nullptr);
    if (!node) {
        return EXIT_FAILURE;
    }
    ret = DPS_StartNode(node, mcast, listenPort);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    DPS_PRINT("Publisher is listening on port %d\n", DPS_GetPortNumber(node));

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node, linkHosts[i], linkPort[i], addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Publisher is linked to %s\n", DPS_NodeAddrToString(addr));
        } else {
            DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
        }
    }

    if (isClient) {
        listener = new PublisherListener();
    }
    if (qos.reliability == dps::DPS_QOS_BEST_EFFORT) {
        publisher = new dps::Publisher(qos, listener);
    } else {
        publisher = new dps::ReliablePublisher(qos, listener);
    }
    ret = publisher->initialize(node, topics);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }

    ReadStdin(publisher);

    ret = publisher->close();
    if (ret != DPS_OK) {
        return ret;
    }
    delete publisher;
    delete listener;
    ret = DestroyNode(node);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    DPS_DestroyAddress(addr);
    return EXIT_SUCCESS;

Usage:
    DPS_PRINT("Usage: %s\n", argv[0]);
    return EXIT_FAILURE;
}
