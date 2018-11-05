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
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/synchronous.h>
#include <dps/Cache.hpp>
#include "common_qos.hpp"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

class PublisherProxy
{
public:
    void ack(uint32_t sn, uint32_t firstSN)
    {
        if (acked_.base_ == 0) {
            acked_.base_ = firstSN;
        }
        acked_.set(sn).shrink(firstSN);
    }

    bool isAcked(uint32_t sn) const
    {
        return acked_.test(sn);
    }

    bool isAvailable(uint32_t sn) const
    {
        return sn < acked_.base_;
    }

    void available(const dps::Range & range)
    {
        range_ = range;
    }

    dps::SNSet missing(size_t avail)
    {
        dps::SNSet complement;

        // messages prior to range.first are considered lost if not already received
        acked_.shrink(range_.first);

        complement.base_ = acked_.base_;
        while (acked_.test(complement.base_) && complement.base_ <= range_.second) {
            ++complement.base_;
        }
        for (uint32_t sn = complement.base_; avail && sn <= range_.second; ++sn) {
            if (!acked_.test(sn)) {
                complement.set(sn);
                --avail;
            }
        }
        return complement;
    }

private:
    dps::Range range_;
    dps::SNSet acked_;
};

typedef struct SubscriberInfo
{
    DPS_UUID uuid_;
    DPS_QoSReliability reliability_;
    dps::Cache<dps::RxStream>* cache_;
    std::map<DPS_UUID, PublisherProxy> pub_;
} SubscriberInfo;

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

static void AckPublication(SubscriberInfo* info, const DPS_Publication* pub, bool force = true)
{
    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);

    if (info->reliability_ == DPS_QOS_RELIABLE && DPS_PublicationIsAckRequested(pub)) {
        dps::SNSet missing = info->pub_[*uuid].missing(info->cache_->capacity() - info->cache_->size());
        if (force || missing.any()) {
            dps::TxStream txBuf;
            Ack ack = { info->uuid_, missing };
            txBuf << ack;
            DPS_Status ret = DPS_AckPublication(pub, txBuf.data(), txBuf.size());
            if (ret != DPS_OK) {
                DPS_PRINT("Ack failed: %s\n", DPS_ErrTxt(ret));
            }
        }
    }
}

static void PubHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    SubscriberInfo* info = (SubscriberInfo*)DPS_GetSubscriptionData(sub);
    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);
    dps::RxStream rxBuf(payload, len);
    dps::Range range;
    uint32_t sn;

    rxBuf >> range;
    info->pub_[*uuid].available(range);
    if (rxBuf.eof()) {
        DPS_PRINT("HEARTBEAT %s [%d,%d]\n", DPS_UUIDToString(uuid), range.first, range.second);
    } else {
        rxBuf >> sn;
        DPS_PRINT("PUB %s(%d) [%d,%d]\n", DPS_UUIDToString(uuid), sn, range.first, range.second);

        if (info->cache_->full()) {
            if (info->reliability_ == DPS_QOS_BEST_EFFORT) {
                info->cache_->removeData(info->cache_->begin());
            }
        }
        if (!info->pub_[*uuid].isAcked(sn) && !info->cache_->full()) {
            dps::Cache<dps::RxStream>::Data data =
                { dps::Publication(DPS_CopyPublication(pub)), sn, std::move(rxBuf) };
            info->cache_->addData(std::move(data));
            if (info->reliability_ == DPS_QOS_BEST_EFFORT) {
                info->pub_[*uuid].ack(sn, sn);
            } else {
                info->pub_[*uuid].ack(sn, range.first);
            }
        }
    }
    AckPublication(info, pub);
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

static void ReadStdin(DPS_Subscription* sub)
{
    SubscriberInfo* info = (SubscriberInfo*)DPS_GetSubscriptionData(sub);
    char lineBuf[256];
    int argc;
    char *argv[MAX_ARGS];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != nullptr) {
        argc = Parse(lineBuf, sizeof(lineBuf), argv);
        if (!strcmp(argv[0], "take")) {
            if (!info->cache_->empty()) {
                const dps::Cache<dps::RxStream>::Data& data = info->cache_->front();
                const DPS_UUID* uuid = DPS_PublicationGetUUID(data.pub_.get());
                if (info->pub_[*uuid].isAvailable(data.sn_)) {
                    dps::Publication pub;
                    uint32_t sn;
                    dps::RxStream buf;
                    info->cache_->takeNextData(pub, sn, buf);
                    DPS_PRINT("%s(%d)\n", DPS_UUIDToString(uuid), sn);
                    AckPublication(info, pub.get(), false);
                }
            }
        } else if (!strcmp(argv[0], "dump")) {
            for (auto it = info->cache_->begin(); it != info->cache_->end(); ++it) {
                DPS_PRINT("%s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
            }
        }
    }
}

#define MAX_LINKS  8

int main(int argc, char** argv)
{
    const char* topics[] = { "A" };
    char** arg = argv + 1;
    int listenPort = 0;
    const char* host = NULL;
    int linkPort[MAX_LINKS];
    const char* linkHosts[MAX_LINKS];
    int numLinks = 0;
    DPS_NodeAddress* addr = nullptr;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    int reliability = DPS_QOS_RELIABLE;
    DPS_Node* node = nullptr;
    DPS_Subscription* sub = nullptr;
    SubscriberInfo* info = nullptr;
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
        if (IntArg("-r", &arg, &argc, &reliability, DPS_QOS_BEST_EFFORT, DPS_QOS_RELIABLE) == 0) {
            continue;
        }
    }
    /*
     * Disable multicast publications if we have an explicit destination
     */
    if (numLinks) {
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
    DPS_PRINT("Subscriber is listening on port %d\n", DPS_GetPortNumber(node));

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node, linkHosts[i], linkPort[i], addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Subscriber is linked to %s\n", DPS_NodeAddrToString(addr));
        } else {
            DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
        }
    }

    sub = DPS_CreateSubscription(node, topics, A_SIZEOF(topics));
    if (!sub) {
        return EXIT_FAILURE;
    }
    info = new SubscriberInfo;
    DPS_GenerateUUID(&info->uuid_);
    info->reliability_ = (DPS_QoSReliability)reliability;
    info->cache_ = new dps::Cache<dps::RxStream>(4);
    ret = DPS_SetSubscriptionData(sub, info);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    ret = DPS_Subscribe(sub, PubHandler);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }

    ReadStdin(sub);

    ret = DPS_DestroySubscription(sub);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    delete info->cache_;
    delete info;
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
