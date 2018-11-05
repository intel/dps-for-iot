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

#include <algorithm>
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

#define HEARTBEAT_PERIOD_MS 1000

class SubscriberProxy
{
public:
  void ack(uint32_t sn)
  {
    base_ = sn;
  }

  bool isAcked(uint32_t sn) const
  {
    return sn <= base_;
  }

private:
  uint32_t base_;
};

typedef struct PublisherInfo
{
    DPS_QoSReliability reliability_;
    uint32_t sn_;
    dps::Cache<dps::TxStream>* cache_;
    std::map<DPS_UUID, SubscriberProxy> sub_;
    uv_async_t async_;
    uv_timer_t timer_;
    DPS_Event* close_;
} PublisherInfo;

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

static void AckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);
    dps::RxStream rxBuf(payload, len);
    Ack ack;

    if (info->reliability_ != DPS_QOS_RELIABLE) {
        return;
    }

    rxBuf >> ack;

    DPS_PRINT("ACK %s(%d)", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), ack.set_.base_ - 1);
    DPS_PRINT(" [ ");
    for (size_t i = 0; i < ack.set_.size(); ++i) {
        if (ack.set_.test(ack.set_.base_ + i)) {
            DPS_PRINT("%d ", ack.set_.base_ + i);
        }
    }
    DPS_PRINT("]");
    DPS_PRINT(" %s\n", DPS_UUIDToString(&ack.uuid_));

    info->sub_[ack.uuid_].ack(ack.set_.base_ - 1);

    for (size_t i = 0; i < ack.set_.size(); ++i) {
        uint32_t sn = ack.set_.base_ + i;
        if (ack.set_.test(sn)) {
            auto it = std::find_if(info->cache_->begin(), info->cache_->end(),
                                   [sn](const dps::Cache<dps::TxStream>::Data& data) {
                                       return data.sn_ == sn;
                                   });
            if (it == info->cache_->end()) {
                DPS_PRINT("Missing publication %d requested\n", sn);
                continue;
            }
            dps::TxStream txBuf;
            dps::Range range = { info->cache_->minSN(), info->cache_->maxSN() };
            txBuf << range << it->sn_ << it->buf_;
            DPS_PRINT("PUB %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)), it->sn_);
            DPS_Status ret = DPS_Publish(pub, txBuf.data(), txBuf.size(), 0);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
            }
        }
    }
}

static bool IsAckedByAll(DPS_Publication* pub, uint32_t sn)
{
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);
    bool is_acked = true;
    for (auto it = info->sub_.begin(); is_acked && it != info->sub_.end(); ++it) {
        is_acked = is_acked && it->second.isAcked(sn);
    }
    return is_acked;
}

static void OnAsyncClose(uv_handle_t* handle)
{
    DPS_Publication* pub = (DPS_Publication*)handle->data;
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);
    DPS_Event* event = info->close_;
    DPS_SignalEvent(event, DPS_OK);
}

static void OnTimerClose(uv_handle_t* handle)
{
    DPS_Publication* pub = (DPS_Publication*)handle->data;
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);
    uv_close((uv_handle_t*)&info->async_, OnAsyncClose);
}

static void OnTimer(uv_timer_t* handle)
{
    DPS_Publication* pub = (DPS_Publication*)handle->data;
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);

    bool is_acked = true;
    for (auto it = info->cache_->begin(); is_acked && it != info->cache_->end(); ++it) {
        is_acked = is_acked && IsAckedByAll(pub, it->sn_);
    }
    if (is_acked) {
        int r = uv_timer_stop(&info->timer_);
        if (r) {
            DPS_ERRPRINT("Timer stop failed: %s\n", uv_strerror(r));
        }
    } else {
        dps::TxStream txBuf;
        dps::Range range = { info->cache_->minSN(), info->cache_->maxSN() };
        txBuf << range;
        DPS_PRINT("HEARTBEAT %s\n", DPS_UUIDToString(DPS_PublicationGetUUID(pub)));
        DPS_Status ret = DPS_Publish(pub, txBuf.data(), txBuf.size(), 0);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void OnAsync(uv_async_t* handle)
{
    DPS_Publication* pub = (DPS_Publication*)handle->data;
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);

    // close all the open handles
    if (info->close_) {
        uv_close((uv_handle_t*)&info->timer_, OnTimerClose);
        return;
    }

    // request acknowledgements for unacknowledged publications
    if (info->reliability_ != DPS_QOS_RELIABLE) {
        return;
    }
    if (!uv_is_active((uv_handle_t*)&info->timer_)) {
        int r = uv_timer_start(&info->timer_, OnTimer, HEARTBEAT_PERIOD_MS, HEARTBEAT_PERIOD_MS);
        if (r) {
            DPS_ERRPRINT("Timer start failed: %s\n", uv_strerror(r));
        }
    }
}

static DPS_Status DestroyInfo(PublisherInfo* info)
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
    r = uv_async_send(&info->async_);
    if (r) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
    }
    ret = DPS_WaitForEvent(event);
    if (ret != DPS_OK) {
        goto Exit;
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

static void ReadStdin(DPS_Publication* pub)
{
    PublisherInfo* info = (PublisherInfo*)DPS_GetPublicationData(pub);
    char lineBuf[256];
    int argc;
    char *argv[MAX_ARGS];

    while (fgets(lineBuf, sizeof(lineBuf), stdin) != nullptr) {
        argc = Parse(lineBuf, sizeof(lineBuf), argv);
        if (!strcmp(argv[0], "pub")) {
            if (info->cache_->full()) {
                if (info->reliability_ == DPS_QOS_BEST_EFFORT) {
                    info->cache_->removeData(info->cache_->begin());
                } else if (info->reliability_ == DPS_QOS_RELIABLE) {
                    for (auto it = info->cache_->begin(); it != info->cache_->end(); ++it) {
                        if (IsAckedByAll(pub, it->sn_)) {
                            info->cache_->removeData(it);
                            break;
                        }
                    }
                }
            }
            // must check for space before adding the data as DPS_Publish must be called before the
            // copied publication will be correct
            if (!info->cache_->full()) {
                dps::TxStream payload(0);
                dps::TxStream buf;
                dps::Range range;
                if (info->cache_->empty()) {
                    range = { info->sn_ + 1, info->sn_ + 1 };
                } else {
                    range = { info->cache_->minSN(), info->sn_ + 1 };
                }
                buf << range << info->sn_ + 1 << payload;
                DPS_Status ret = DPS_Publish(pub, buf.data(), buf.size(), 0);
                if (ret == DPS_OK) {
                    dps::Cache<dps::TxStream>::Data data =
                        { dps::Publication(DPS_CopyPublication(pub)), info->sn_ + 1, std::move(payload) };
                    info->cache_->addData(std::move(data));
                    ++info->sn_;
                    int r = uv_async_send(&info->async_);
                    if (r) {
                        DPS_ERRPRINT("Async send failed: %s\n", uv_strerror(r));
                    }
                }
            } else {
                DPS_PRINT("%s\n", DPS_ErrTxt(DPS_ERR_OVERFLOW));
            }
        } else if (!strcmp(argv[0], "drop")) {
            if (!info->cache_->empty()) {
                info->cache_->removeData(info->cache_->begin());
            }
            ++info->sn_;
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
    DPS_Node* node = nullptr;
    DPS_AcknowledgementHandler handler;
    DPS_Publication* pub = nullptr;
    DPS_QoS qos = { 64 };       /* TODO This is only to allow back-to-back publications */
    int reliability = DPS_QOS_RELIABLE;
    PublisherInfo* info = nullptr;
    size_t i;
    DPS_Status ret;
    int r;

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
    DPS_PRINT("Publisher is listening on port %d\n", DPS_GetPortNumber(node));

    for (i = 0; i < numLinks; ++i) {
        ret = DPS_LinkTo(node, linkHosts[i], linkPort[i], addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Publisher is linked to %s\n", DPS_NodeAddrToString(addr));
        } else {
            DPS_ERRPRINT("DPS_LinkTo %d returned %s\n", linkPort[i], DPS_ErrTxt(ret));
        }
    }

    pub = DPS_CreatePublication(node);
    if (!pub) {
        return EXIT_FAILURE;
    }
    handler = (reliability == DPS_QOS_RELIABLE) ? AckHandler : nullptr;
    ret = DPS_InitPublication(pub, topics, A_SIZEOF(topics), DPS_FALSE, nullptr, handler);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    ret = DPS_PublicationConfigureQoS(pub, &qos);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    info = new PublisherInfo;
    info->reliability_ = (DPS_QoSReliability)reliability;
    info->sn_ = DPS_PublicationGetSequenceNum(pub);
    info->cache_ = new dps::Cache<dps::TxStream>(4);
    r = uv_async_init(DPS_GetLoop(node), &info->async_, OnAsync);
    if (r) {
        return EXIT_FAILURE;
    }
    info->async_.data = pub;
    r = uv_timer_init(DPS_GetLoop(node), &info->timer_);
    if (r) {
        return EXIT_FAILURE;
    }
    info->timer_.data = pub;
    info->close_ = nullptr;
    ret = DPS_SetPublicationData(pub, info);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }

    ReadStdin(pub);

    ret = DPS_DestroyPublication(pub);
    if (ret != DPS_OK) {
        return EXIT_FAILURE;
    }
    ret = DestroyInfo(info);
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
