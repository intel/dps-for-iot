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
#include <dps/private/loop.h>
#include <dps/Cache.hpp>
#include "common_qos.hpp"

#define A_SIZEOF(a)  (sizeof(a) / sizeof((a)[0]))

#define REGISTER_PERIOD_MS 1000
#define ALIVE_TIMEOUT_MS 3000

typedef struct PublisherProxy
{
    dps::Range range_;
    dps::SNSet acked_;
    dps::Publication pub_;
    uv_timer_t timer_;
    uint64_t alive_;

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
} PublisherProxy;

typedef struct SubscriberInfo
{
    DPS_UUID uuid_;
    DPS_QoSReliability reliability_;
    dps::Cache<dps::RxStream>* cache_;
    std::map<DPS_UUID, PublisherProxy> pub_;
    DPS_Event* close_;
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

typedef std::pair<SubscriberInfo*, DPS_UUID> RegisterData;

static void OnTimerCloseSignal(uv_handle_t* handle)
{
    RegisterData* data = (RegisterData*)handle->data;
    SubscriberInfo* info = data->first;
    DPS_Event* event = info->close_;
    DPS_SignalEvent(event, DPS_OK);
    delete data;
}

static void OnTimerCloseErase(uv_handle_t* handle)
{
    RegisterData* data = (RegisterData*)handle->data;
    SubscriberInfo* info = data->first;
    const DPS_UUID* uuid = &data->second;
    info->pub_.erase(*uuid);
    delete data;
}

static void OnTimer(uv_timer_t* handle)
{
    RegisterData* data = (RegisterData*)handle->data;
    SubscriberInfo* info = data->first;
    const DPS_UUID* uuid = &data->second;

    // remove a dead publisher
    uint64_t now = uv_now(DPS_GetLoop(DPS_PublicationGetNode(info->pub_[*uuid].pub_.get())));
    if (now - info->pub_[*uuid].alive_ >= ALIVE_TIMEOUT_MS) {
        DPS_PRINT("Publisher %s is dead\n", DPS_UUIDToString(uuid));
        uv_close((uv_handle_t*)&info->pub_[*uuid].timer_, OnTimerCloseErase);
        return;
    }

    // register this subscriber with a publisher
    dps::TxStream buf;
    buf << info->uuid_;
    DPS_Status ret = DPS_Publish(info->pub_[*uuid].pub_.get(), buf.data(), buf.size(), 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
    }
}

static void RegisterAckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    RegisterData* data = (RegisterData*)DPS_GetPublicationData(pub);
    SubscriberInfo* info = data->first;
    const DPS_UUID* uuid = &data->second;
    dps::RxStream rxBuf(payload, len);
    dps::Range range;

    rxBuf >> range;
    DPS_PRINT("REGISTER %s [%d,%d]\n", DPS_UUIDToString(uuid), range.first, range.second);

    info->pub_[*uuid].available(range);
    info->pub_[*uuid].ack(range.second, range.second);
    info->pub_[*uuid].alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub)));

    int r = uv_timer_stop(&info->pub_[*uuid].timer_);
    if (r) {
        DPS_ERRPRINT("Timer stop failed: %s\n", uv_strerror(r));
    }
}

static DPS_Status Register(SubscriberInfo* info, DPS_Node* node, const DPS_UUID* uuid)
{
    DPS_Status ret = DPS_OK;
    int r;

    if (!info->pub_[*uuid].pub_) {
        dps::Publication pub = dps::Publication(DPS_CreatePublication(node));
        if (!pub) {
            return DPS_ERR_RESOURCES;
        }
        const char* topic = DPS_UUIDToString(uuid);
        ret = DPS_InitPublication(pub.get(), &topic, 1, DPS_TRUE, NULL, RegisterAckHandler);
        if (ret != DPS_OK) {
            return ret;
        }
        RegisterData* data = new RegisterData(info, *uuid);
        ret = DPS_SetPublicationData(pub.get(), data);
        if (ret != DPS_OK) {
            return ret;
        }
        r = uv_timer_init(DPS_GetLoop(node), &info->pub_[*uuid].timer_);
        if (r) {
            return DPS_ERR_FAILURE;
        }
        info->pub_[*uuid].pub_ = std::move(pub);
        info->pub_[*uuid].timer_.data = data;
    }

    if (!uv_is_active((uv_handle_t*)&info->pub_[*uuid].timer_)) {
        r = uv_timer_start(&info->pub_[*uuid].timer_, OnTimer, 0, REGISTER_PERIOD_MS);
        if (r) {
            DPS_ERRPRINT("Timer start failed: %s\n", uv_strerror(r));
            return DPS_ERR_FAILURE;
        }
    }

    return DPS_OK;
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

    if (info->reliability_ == DPS_QOS_RELIABLE && DPS_PublicationIsAckRequested(pub) &&
        info->pub_.find(*uuid) == info->pub_.end()) {
        // if this is a new publisher, we need to register first
        // before we start accepting messages, otherwise the publisher
        // may discard messages before it knows we are here
        DPS_Status ret = Register(info, DPS_SubscriptionGetNode(sub), DPS_PublicationGetUUID(pub));
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Register failed: %s\n", DPS_ErrTxt(ret));
            return;
        }
    }
    info->pub_[*uuid].alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub)));
    if (info->pub_[*uuid].pub_ && uv_is_active((uv_handle_t*)&info->pub_[*uuid].timer_)) {
        // waiting for registration ack from publisher
        return;
    }

    rxBuf >> range;
    info->pub_[*uuid].available(range);
    if (!rxBuf.eof()) {
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

static DPS_Status DestroyInfo(SubscriberInfo* info)
{
    DPS_Event* event = nullptr;
    DPS_Status ret;
    int r;

    event = DPS_CreateEvent();
    if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    info->close_ = event;
    for (auto it = info->pub_.begin(); it != info->pub_.end(); ++it) {
        if (!it->second.pub_) {
            continue;
        }
        uv_close((uv_handle_t*)&it->second.timer_, OnTimerCloseSignal);
        ret = DPS_WaitForEvent(event);
        if (ret != DPS_OK) {
            goto Exit;
        }
    }
    delete info->cache_;
    delete info;

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
            DPS_PRINT("Cache\n");
            for (auto it = info->cache_->begin(); it != info->cache_->end(); ++it) {
                DPS_PRINT("  %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
            }
            DPS_PRINT("Publishers\n");
            for (auto it = info->pub_.begin(); it != info->pub_.end(); ++it) {
                DPS_PRINT("  %s [%d,%d]\n", DPS_UUIDToString(&it->first),
                          it->second.range_.first, it->second.range_.second);
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
    info->close_ = nullptr;
    ret = DPS_SetSubscriptionData(sub, info);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    ret = DPS_Subscribe(sub, PubHandler);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }

    ReadStdin(sub);

    ret = DestroyInfo(info);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    ret = DPS_DestroySubscription(sub);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
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
