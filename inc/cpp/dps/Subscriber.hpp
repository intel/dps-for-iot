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

#ifndef _DPS_SUBSCRIBER_HPP
#define _DPS_SUBSCRIBER_HPP

#include <map>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/private/loop.h>
#include <dps/Cache.hpp>
#include <dps/QoS.hpp>

namespace dps
{

class Subscriber;

class SubscriberListener
{
public:
  virtual
  ~SubscriberListener()
  {
  }
  virtual void
  onNewPublication(Subscriber * subscriber) = 0;
};

class Subscriber
{
public:
  Subscriber(QoS & qos, SubscriberListener * listener)
    : sub_(nullptr), qos_(qos), cache_(new Cache<RxStream>(qos_.depth)), close_(nullptr), listener_(listener)
  {
    DPS_GenerateUUID(&uuid_);
  }
  ~Subscriber()
  {
    delete cache_;
  }

  DPS_Status
  initialize(DPS_Node * node, const std::vector<std::string> & topics)
  {
    std::vector<const char *> ctopics;
    DPS_Status ret = DPS_OK;
    std::transform(topics.begin(), topics.end(), std::back_inserter(ctopics),
                   [](const std::string & s) { return s.c_str(); });
    sub_ = DPS_CreateSubscription(node, ctopics.data(), ctopics.size());
    if (!sub_) {
      ret = DPS_ERR_RESOURCES;
      goto Exit;
    }
    ret = DPS_SetSubscriptionData(sub_, this);
    if (ret != DPS_OK) {
      goto Exit;
    }
    ret = DPS_Subscribe(sub_, pubHandler_);
    if (ret != DPS_OK) {
      goto Exit;
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
    DPS_Status ret = DPS_OK;

    event = DPS_CreateEvent();
    if (!event) {
      ret = DPS_ERR_RESOURCES;
      goto Exit;
    }
    close_ = event;
    for (auto it = pub_.begin(); it != pub_.end(); ++it) {
      if (!it->second.pub_) {
        continue;
      }
      uv_close((uv_handle_t *)&it->second.timer_, onTimerCloseSignal_);
      ret = DPS_WaitForEvent(event);
      if (ret != DPS_OK) {
        goto Exit;
      }
    }
    ret = DPS_DestroySubscription(sub_);
    if (ret != DPS_OK) {
      goto Exit;
    }
    sub_ = nullptr;
  Exit:
    DPS_DestroyEvent(event);
    return ret;
  }

  size_t
  unreadCount()
  {
    return cache_->size();
  }
  bool
  takeNextData(RxStream & buf, PublicationInfo & info)
  {
    if (cache_->empty()) {
      return false;
    }
    const Cache<RxStream>::Data & data = cache_->front();
    DPS_Publication * pub = data.pub_.get();
    const DPS_UUID * uuid = DPS_PublicationGetUUID(pub);
    if (pub_[*uuid].isAvailable(data.sn_)) {
      cache_->takeNextData(buf, info);
      ackPublication(pub, false);
    }
    return true;
  }

  void
  dump()
  {
    DPS_PRINT("Cache\n");
    for (auto it = cache_->begin(); it != cache_->end(); ++it) {
      DPS_PRINT("  %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
    }
    DPS_PRINT("Publishers\n");
    for (auto it = pub_.begin(); it != pub_.end(); ++it) {
      DPS_PRINT("  %s [%d,%d]\n", DPS_UUIDToString(&it->first),
                it->second.range_.first, it->second.range_.second);
    }
  }

private:
  typedef struct RemotePublisher
  {
    Range range_;
    SNSet acked_;
    Publication pub_;
    uv_timer_t timer_;
    uint64_t alive_;

    void
    ack(uint32_t sn, uint32_t firstSN)
    {
      if (acked_.base_ == 0) {
        acked_.base_ = firstSN;
      }
      acked_.set(sn).shrink(firstSN);
    }
    bool
    isAcked(uint32_t sn) const
    {
      return acked_.test(sn);
    }
    bool
    isAvailable(uint32_t sn) const
    {
      return sn < acked_.base_;
    }
    void
    available(const Range & range)
    {
      range_ = range;
    }
    SNSet
    missing(size_t avail)
    {
      SNSet complement;

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
  } RemotePublisher;
  typedef std::pair<Subscriber *, DPS_UUID> AddSubscriberData;

  static const uint64_t registerPeriodMs = 1000;
  static const uint64_t aliveTimeoutMs = 3000;

  DPS_Subscription* sub_;
  DPS_UUID uuid_;
  QoS qos_;
  Cache<RxStream> * cache_;
  std::map<DPS_UUID, RemotePublisher> pub_;
  DPS_Event * close_;
  SubscriberListener * listener_;

  static void
  pubHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    Subscriber * subscriber = static_cast<Subscriber *>(DPS_GetSubscriptionData(sub));
    subscriber->pubHandler(pub, data, dataLen);
  }
  static void
  addSubscriberAckHandler_(DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    AddSubscriberData* d = static_cast<AddSubscriberData *>(DPS_GetPublicationData(pub));
    Subscriber * subscriber = d->first;
    const DPS_UUID * uuid = &d->second;
    subscriber->addSubscriberAckHandler(pub, uuid, data, dataLen);
  }
  static void
  onTimerCloseSignal_(uv_handle_t * handle)
  {
    AddSubscriberData * data = static_cast<AddSubscriberData *>(handle->data);
    Subscriber * subscriber = data->first;
    DPS_SignalEvent(subscriber->close_, DPS_OK);
    delete data;
  }
  static void
  onTimerCloseErase_(uv_handle_t * handle)
  {
    AddSubscriberData * data = static_cast<AddSubscriberData *>(handle->data);
    Subscriber * subscriber = data->first;
    const DPS_UUID * uuid = &data->second;
    subscriber->pub_.erase(*uuid);
    delete data;
  }
  static void
  onTimer_(uv_timer_t * handle)
  {
    AddSubscriberData * data = static_cast<AddSubscriberData *>(handle->data);
    Subscriber * subscriber = data->first;
    const DPS_UUID * uuid = &data->second;
    subscriber->onTimer(uuid);
  }

  void
  pubHandler(const DPS_Publication * pub, uint8_t * data, size_t dataLen)
  {
    const DPS_UUID * uuid = DPS_PublicationGetUUID(pub);
    RxStream rxBuf(data, dataLen);
    Range range;
    uint32_t sn;

    if (qos_.reliability == DPS_QOS_RELIABLE && DPS_PublicationIsAckRequested(pub) &&
        pub_.find(*uuid) == pub_.end()) {
      // if this is a new publisher, we need to register first
      // before we start accepting messages, otherwise the publisher
      // may discard messages before it knows we are here
      DPS_Status ret = addSubscriber(DPS_PublicationGetUUID(pub));
      if (ret != DPS_OK) {
        DPS_ERRPRINT("Add subscriber failed: %s\n", DPS_ErrTxt(ret));
        return;
      }
    }
    pub_[*uuid].alive_ = uv_now(DPS_GetLoop(DPS_SubscriptionGetNode(sub_)));
    if (pub_[*uuid].pub_ && uv_is_active((uv_handle_t *)&pub_[*uuid].timer_)) {
      // waiting for registration ack from publisher
      return;
    }

    rxBuf >> range;
    pub_[*uuid].available(range);
    if (!rxBuf.eof()) {
      rxBuf >> sn;

      if (cache_->full()) {
        if (qos_.reliability == DPS_QOS_BEST_EFFORT) {
          cache_->removeData(cache_->begin());
        }
      }
      if (!pub_[*uuid].isAcked(sn) && !cache_->full()) {
        Cache<RxStream>::Data data =
          { Publication(DPS_CopyPublication(pub)), sn, std::move(rxBuf) };
        cache_->addData(std::move(data));
        if (qos_.reliability == DPS_QOS_BEST_EFFORT) {
          pub_[*uuid].ack(sn, sn);
        } else {
          pub_[*uuid].ack(sn, range.first);
        }
        listener_->onNewPublication(this);
      }
    }
    ackPublication(pub);
  }

  void
  addSubscriberAckHandler(DPS_Publication * pub, const DPS_UUID * uuid, uint8_t * data, size_t dataLen)
  {
    RxStream rxBuf(data, dataLen);
    Range range;

    rxBuf >> range;

    pub_[*uuid].available(range);
    // TODO this assumes VOLATILE for now, for TRANSIENT, use range.first - 1
    pub_[*uuid].ack(range.second, range.second);
    pub_[*uuid].alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub)));

    int err = uv_timer_stop(&pub_[*uuid].timer_);
    if (err) {
      DPS_ERRPRINT("uv_timer_stop failed: %s\n", uv_strerror(err));
    }
  }

  void
  onTimer(const DPS_UUID * uuid)
  {
    // remove a dead publisher
    uint64_t now = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub_[*uuid].pub_.get())));
    if (now - pub_[*uuid].alive_ >= aliveTimeoutMs) {
      uv_close((uv_handle_t*)&pub_[*uuid].timer_, onTimerCloseErase_);
      return;
    }

    // register this subscriber with a publisher
    TxStream buf;
    buf << uuid_;
    DPS_Status ret = DPS_Publish(pub_[*uuid].pub_.get(), buf.data(), buf.size(), 0);
    if (ret != DPS_OK) {
      DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
    }
  }

  DPS_Status
  addSubscriber(const DPS_UUID * uuid)
  {
    DPS_Node * node = DPS_SubscriptionGetNode(sub_);
    DPS_Status ret = DPS_OK;
    int err;

    if (!pub_[*uuid].pub_) {
      Publication pub = Publication(DPS_CreatePublication(node));
      if (!pub) {
        return DPS_ERR_RESOURCES;
      }
      const char* topic = DPS_UUIDToString(uuid);
      ret = DPS_InitPublication(pub.get(), &topic, 1, DPS_TRUE, NULL, addSubscriberAckHandler_);
      if (ret != DPS_OK) {
        return ret;
      }
      AddSubscriberData* data = new AddSubscriberData(this, *uuid);
      ret = DPS_SetPublicationData(pub.get(), data);
      if (ret != DPS_OK) {
        return ret;
      }
      err = uv_timer_init(DPS_GetLoop(node), &pub_[*uuid].timer_);
      if (err) {
        return DPS_ERR_FAILURE;
      }
      pub_[*uuid].pub_ = std::move(pub);
      pub_[*uuid].timer_.data = data;
    }

    if (!uv_is_active((uv_handle_t*)&pub_[*uuid].timer_)) {
      err = uv_timer_start(&pub_[*uuid].timer_, onTimer_, 0, registerPeriodMs);
      if (err) {
        return DPS_ERR_FAILURE;
      }
    }

    return DPS_OK;
  }

  void
  ackPublication(const DPS_Publication * pub, bool force = true)
  {
    const DPS_UUID* uuid = DPS_PublicationGetUUID(pub);

    if (qos_.reliability == DPS_QOS_RELIABLE && DPS_PublicationIsAckRequested(pub)) {
      SNSet missing = pub_[*uuid].missing(cache_->capacity() - cache_->size());
      if (force || missing.any()) {
        TxStream txBuf;
        Ack ack = { uuid_, missing };
        txBuf << ack;
        DPS_Status ret = DPS_AckPublication(pub, txBuf.data(), txBuf.size());
        if (ret != DPS_OK) {
          DPS_ERRPRINT("Ack failed: %s\n", DPS_ErrTxt(ret));
        }
      }
    }
  }

};

}

#endif
