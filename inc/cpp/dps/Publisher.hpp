// -*- mode: C++; c-basic-offset: 2; -*-
// Copyright 2018 Intel Corporation All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _DPS_PUBLISHER_HPP
#define _DPS_PUBLISHER_HPP

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <map>
#include <dps/dps.h>
#include <dps/private/loop.h>
#include <dps/Cache.hpp>
#include <dps/QoS.hpp>

namespace dps
{

class Publisher
{
public:
  Publisher(QoS & qos)
  : pub_(nullptr), sn_(0), qos_(qos), cache_(new Cache<TxStream>(qos_.depth)), thisSub_(nullptr), close_(nullptr)
  {
  }
  ~Publisher()
  {
    delete cache_;
  }

  DPS_Status
  initialize(DPS_Node * node, const std::vector<std::string> & topics)
  {
    int err;
    DPS_QoS qos = { 64 }; // TODO This is only to allow back-to-back publications
    DPS_AcknowledgementHandler handler = nullptr;
    std::vector<const char *> ctopics;
    DPS_Status ret = DPS_OK;
    pub_ = DPS_CreatePublication(node);
    if (!pub_) {
      ret = DPS_ERR_RESOURCES;
      goto Exit;
    }
    std::transform(topics.begin(), topics.end(), std::back_inserter(ctopics),
                   [](const std::string & s) { return s.c_str(); });
    handler = (qos_.reliability == DPS_QOS_RELIABLE) ? ackHandler_ : nullptr;
    ret = DPS_InitPublication(pub_, ctopics.data(), ctopics.size(), DPS_FALSE, nullptr, handler);
    if (ret != DPS_OK) {
      goto Exit;
    }
    sn_ = DPS_PublicationGetSequenceNum(pub_);
    ret = DPS_PublicationConfigureQoS(pub_, &qos);
    if (ret != DPS_OK) {
      goto Exit;
    }
    ret = DPS_SetPublicationData(pub_, this);
    if (ret != DPS_OK) {
      goto Exit;
    }
    if (qos_.reliability == DPS_QOS_RELIABLE) {
      const char* uuid = DPS_UUIDToString(DPS_PublicationGetUUID(pub_));
      thisSub_ = DPS_CreateSubscription(node, &uuid, 1);
      if (!thisSub_) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
      }
      ret = DPS_SetSubscriptionData(thisSub_, this);
      if (ret != DPS_OK) {
        goto Exit;
      }
      err = uv_async_init(DPS_GetLoop(node), &async_, onAsync_);
      if (err) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
      }
      async_.data = this;
      err = uv_timer_init(DPS_GetLoop(node), &timer_);
      if (err) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
      }
      timer_.data = this;

      ret = DPS_Subscribe(thisSub_, pubHandler_);
      if (ret != DPS_OK) {
        goto Exit;
      }
      err = uv_async_send(&async_);
      if (err) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
      }
    }
  Exit:
    if (ret != DPS_OK) {
      close();
    }
    return ret;
  }
  DPS_Status
  close()
  {
    DPS_Event* event = nullptr;
    DPS_Status ret;
    int r;

    if (qos_.reliability == DPS_QOS_RELIABLE) {
      event = DPS_CreateEvent();
      if (!event) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
      }
      close_ = event;
      r = uv_async_send(&async_);
      if (r) {
        ret = DPS_ERR_FAILURE;
        goto Exit;
      }
      ret = DPS_WaitForEvent(event);
      if (ret != DPS_OK) {
        goto Exit;
      }
      ret = DPS_DestroySubscription(thisSub_);
      if (ret != DPS_OK) {
        goto Exit;
      }
      thisSub_ = nullptr;
    }
    ret = DPS_DestroyPublication(pub_);
    if (ret != DPS_OK) {
      goto Exit;
    }
    pub_ = nullptr;
  Exit:
    DPS_DestroyEvent(event);
    close_ = nullptr;
    return ret;
  }

  DPS_Status
  publish(const uint8_t * data, size_t dataLen, int16_t ttl = 0)
  {
    if (cache_->full()) {
      if (qos_.reliability == DPS_QOS_BEST_EFFORT) {
        cache_->removeData(cache_->begin());
      } else if (qos_.reliability == DPS_QOS_RELIABLE) {
        for (auto it = cache_->begin(); it != cache_->end(); ++it) {
          if (isAckedByAll(it->sn_)) {
            cache_->removeData(it);
            break;
          }
        }
      }
    }
    // must check for space before adding the data as DPS_Publish must be called before the
    // copied publication will be correct
    if (!cache_->full()) {
      Range range;
      if (cache_->empty()) {
        range = { sn_ + 1, sn_ + 1 };
      } else {
        range = { cache_->minSN(), sn_ + 1 };
      }
      TxStream payload(data, dataLen);
      TxStream buf;
      buf << range << sn_ + 1 << payload;
      DPS_Status ret = DPS_Publish(pub_, buf.data(), buf.size(), ttl);
      if (ret == DPS_OK) {
        Cache<TxStream>::Data data =
          { Publication(DPS_CopyPublication(pub_)), sn_ + 1, std::move(payload) };
        cache_->addData(std::move(data));
        ++sn_;
        resetHeartbeat();
      }
      return ret;
    } else {
      return DPS_ERR_OVERFLOW;
    }
  }

  void
  dump()
  {
    DPS_PRINT("Cache\n");
    for (auto it = cache_->begin(); it != cache_->end(); ++it) {
      DPS_PRINT("  %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
    }
    DPS_PRINT("Subscribers (reliable)\n");
    for (auto it = sub_.begin(); it != sub_.end(); ++it) {
      DPS_PRINT("  %s ack=%d alive=%" PRIu64 "\n", DPS_UUIDToString(&it->first), it->second.base_,
                it->second.alive_);
    }
  }

private:
  typedef struct RemoteSubscriber
  {
    uint32_t base_;
    uint64_t alive_;
    void ack(uint32_t sn) { base_ = sn; }
    bool isAcked(uint32_t sn) const { return sn <= base_; }
  } RemoteSubscriber;

  static const uint64_t heartbeatPeriodMs = 1000;
  static const uint64_t aliveTimeoutMs = 3000;

  DPS_Publication * pub_;
  uint32_t sn_;
  QoS qos_;
  Cache<TxStream> * cache_;
  DPS_Subscription * thisSub_;
  uv_async_t async_;
  uv_timer_t timer_;
  std::map<DPS_UUID, RemoteSubscriber> sub_;
  DPS_Event * close_;

  static void
  ackHandler_(DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    Publisher * publisher = static_cast<Publisher *>(DPS_GetPublicationData(pub));
    publisher->ackHandler(data, dataLen);
  }
  static void
  pubHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    Publisher * publisher = static_cast<Publisher *>(DPS_GetSubscriptionData(sub));
    publisher->pubHandler(pub, data, dataLen);
  }
  static void
  onAsync_(uv_async_t * handle)
  {
    Publisher * publisher = static_cast<Publisher *>(handle->data);
    publisher->onAsync();
  }
  static void
  onTimer_(uv_timer_t * handle)
  {
    Publisher * publisher = static_cast<Publisher *>(handle->data);
    publisher->onTimer();
  }
  static void
  onTimerClose_(uv_handle_t * handle)
  {
    Publisher * publisher = static_cast<Publisher *>(handle->data);
    uv_close((uv_handle_t *)&publisher->async_, onAsyncClose_);
  }
  static void
  onAsyncClose_(uv_handle_t * handle)
  {
    Publisher * publisher = static_cast<Publisher *>(handle->data);
    DPS_SignalEvent(publisher->close_, DPS_OK);
  }

  void
  resetHeartbeat()
  {
    int err = uv_async_send(&async_);
    if (err) {
      DPS_ERRPRINT("uv_async_send failed: %s\n", uv_strerror(err));
    }
  }

  bool
  isAckedByAll(uint32_t sn)
  {
    // remove dead subscribers
    uint64_t now = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub_)));
    for (auto it = sub_.begin(); it != sub_.end(); ) {
      if (now - it->second.alive_ >= aliveTimeoutMs) {
        it = sub_.erase(it);
      } else {
        ++it;
      }
    }
    // check if the serial number has been acknowledged by all subscribers
    bool isAcked = true;
    for (auto it = sub_.begin(); isAcked && it != sub_.end(); ++it) {
      isAcked = isAcked && it->second.isAcked(sn);
    }
    return isAcked;
  }

  void
  ackHandler(uint8_t * data, size_t dataLen)
  {
    RxStream rxBuf(data, dataLen);
    Ack ack;

    assert(qos_.reliability == DPS_QOS_RELIABLE);

    rxBuf >> ack;

    sub_[ack.uuid_].ack(ack.set_.base_ - 1);
    sub_[ack.uuid_].alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub_)));

    for (size_t i = 0; i < ack.set_.size(); ++i) {
      uint32_t sn = ack.set_.base_ + i;
      if (ack.set_.test(sn)) {
        auto it = std::find_if(cache_->begin(), cache_->end(),
                               [sn](const Cache<TxStream>::Data& data) {
                                 return data.sn_ == sn;
                               });
        if (it == cache_->end()) {
          // stale publication requested
          continue;
        }
        TxStream txBuf;
        Range range = { cache_->minSN(), cache_->maxSN() };
        txBuf << range << it->sn_ << it->buf_;
        DPS_Status ret = DPS_Publish(pub_, txBuf.data(), txBuf.size(), 0);
        if (ret == DPS_OK) {
          resetHeartbeat();
        } else {
          DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
        }
      }
    }
  }

  void
  pubHandler(const DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    if (!DPS_PublicationIsAckRequested(pub)) {
        return;
    }

    RxStream rxBuf(data, dataLen);
    DPS_UUID uuid;

    rxBuf >> uuid;

    Range range;
    if (cache_->empty()) {
        range = { 0, 0 };
    } else {
        range = { cache_->minSN(), cache_->maxSN() };
    }
    // TODO this assumes VOLATILE for now, for TRANSIENT, use range.first - 1:
    sub_[uuid].ack(range.second);
    sub_[uuid].alive_ = uv_now(DPS_GetLoop(DPS_SubscriptionGetNode(thisSub_)));

    TxStream txBuf;
    txBuf << range;
    DPS_Status ret = DPS_AckPublication(pub, txBuf.data(), txBuf.size());
    if (ret != DPS_OK) {
      DPS_ERRPRINT("Ack failed: %s\n", DPS_ErrTxt(ret));
    }
  }

  void
  onAsync()
  {
    assert(qos_.reliability == DPS_QOS_RELIABLE);
    // close all the open handles
    if (close_) {
      uv_close((uv_handle_t *)&timer_, onTimerClose_);
      return;
    }
    // request acknowledgements for unacknowledged publications
    if (!uv_is_active((uv_handle_t *)&timer_)) {
      int err = uv_timer_start(&timer_, onTimer_, heartbeatPeriodMs, heartbeatPeriodMs);
      if (err) {
        DPS_ERRPRINT("uv_timer_start failed: %s\n", uv_strerror(err));
      }
    } else {
      int err = uv_timer_again(&timer_);
      if (err) {
        DPS_ERRPRINT("uv_timer_again failed: %s\n", uv_strerror(err));
      }
    }
  }

  void
  onTimer()
  {
    // send out a new heartbeat
    Range range;
    if (cache_->empty()) {
      range = { 0, 0 };
    } else {
      range = { cache_->minSN(), cache_->maxSN() };
    }
    TxStream txBuf;
    txBuf << range;
    DPS_Status ret = DPS_Publish(pub_, txBuf.data(), txBuf.size(), 0);
    if (ret != DPS_OK) {
      DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
    }
  }
};

}

#endif
