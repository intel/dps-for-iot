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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <dps/dps.h>
#include <dps/private/loop.h>
#include <dps/Publisher.hpp>
#include <dps/Subscriber.hpp>

using namespace dps;

class ReliablePublisher::Subscriber : public ReliableSubscriber
{
public:
  ReliablePublisher * publisher_;

  Subscriber(const QoS & qos, ReliablePublisher * publisher, const DPS_UUID * uuid);
  virtual ~Subscriber() {}
  virtual void pubHandler(const DPS_Publication * pub, PublicationHeader & header, RxStream & rxBuf);
};

Publisher::Publisher(const QoS & qos, PublisherListener * listener)
  : qos_(qos), listener_(listener), pub_(nullptr), sn_(0), cache_(new Cache<TxStream>(qos.depth)),
    thisSub_(nullptr), close_(nullptr)
{
  if (qos_.durability == DPS_QOS_VOLATILE) {
    heartbeatPolicy_ = HEARTBEAT_NEVER;
  } else if (qos_.durability == DPS_QOS_TRANSIENT) {
    heartbeatPolicy_ = HEARTBEAT_ALWAYS;
  }
}

Publisher::~Publisher()
{
  delete thisSub_;
  delete cache_;
}

DPS_Status Publisher::initialize(DPS_Node * node, const std::vector<std::string> & topics)
{
  DPS_Status ret;
  std::lock_guard<std::recursive_mutex> lock(internalMutex_);
  DPS_AcknowledgementHandler handler = (qos_.durability == DPS_QOS_VOLATILE) ? nullptr: ackHandler_;
  ret = initialize(node, topics, handler);
  if (ret != DPS_OK) {
    goto Exit;
  }
  if (listener_) {
    thisSub_ = new Subscriber(qos_, this, uuid());
    std::vector<std::string> thisTopic = { DPS_UUIDToString(uuid()) };
    ret = thisSub_->initialize(node, thisTopic);
    if (ret != DPS_OK) {
      goto Exit;
    }
  }
Exit:
  if (ret != DPS_OK) {
    close();
  }
  return ret;
}

DPS_Status Publisher::initialize(DPS_Node * node, const std::vector<std::string> & topics,
                                 DPS_AcknowledgementHandler handler)
{
  DPS_QoS qos = { 64 }; // TODO This is only to allow back-to-back publications
  std::vector<const char *> ctopics;
  DPS_Status ret = DPS_OK;
  int err;
  pub_ = DPS_CreatePublication(node);
  if (!pub_) {
    return DPS_ERR_RESOURCES;
  }
  std::transform(topics.begin(), topics.end(), std::back_inserter(ctopics),
                 [](const std::string & s) { return s.c_str(); });
  ret = DPS_InitPublication(pub_, ctopics.data(), ctopics.size(), DPS_FALSE, nullptr, handler);
  if (ret != DPS_OK) {
    return ret;
  }
  sn_ = DPS_PublicationGetSequenceNum(pub_);
  ret = DPS_PublicationConfigureQoS(pub_, &qos);
  if (ret != DPS_OK) {
    return ret;
  }
  ret = DPS_SetPublicationData(pub_, this);
  if (ret != DPS_OK) {
    return ret;
  }
  err = uv_async_init(DPS_GetLoop(node), &async_, onAsync_);
  if (err) {
    return DPS_ERR_FAILURE;
  }
  async_.data = this;
  err = uv_timer_init(DPS_GetLoop(node), &timer_);
  if (err) {
    return DPS_ERR_FAILURE;
  }
  timer_.data = this;
  return DPS_OK;
}

DPS_Status Publisher::close()
{
  DPS_Event* event = nullptr;
  DPS_Status ret;
  int err;
  event = DPS_CreateEvent();
  if (!event) {
    ret = DPS_ERR_RESOURCES;
    goto Exit;
  }
  close_ = event;
  err = uv_async_send(&async_);
  if (err) {
    ret = DPS_ERR_FAILURE;
    goto Exit;
  }
  ret = DPS_WaitForEvent(event);
  if (ret != DPS_OK) {
    goto Exit;
  }
  if (thisSub_) {
    ret = thisSub_->close();
    if (ret != DPS_OK) {
      return ret;
    }
  }
  ret = DPS_DestroyPublication(pub_);
  if (ret != DPS_OK) {
    return ret;
  }
  pub_ = nullptr;
Exit:
  DPS_DestroyEvent(event);
  close_ = nullptr;
  return ret;
}

DPS_Status Publisher::publish(TxStream && payload, PublicationInfo * info)
{
  std::lock_guard<std::recursive_mutex> lock(internalMutex_);
  if (cache_->full()) {
    cache_->removeData(cache_->begin());
  }
  return addPublication(std::move(payload), info);
}

const DPS_UUID * Publisher::uuid() const
{
  return DPS_PublicationGetUUID(pub_);
}

size_t Publisher::unreadCount()
{
  return thisSub_ ? thisSub_->unreadCount() : 0;
}

bool Publisher::takeNextData(RxStream & buf, PublicationInfo & info)
{
  std::lock_guard<std::recursive_mutex> lock(internalMutex_);
  bool hasData = thisSub_ ? thisSub_->takeNextData(buf, info) : false;
  if (hasData) {
    buf >> info.uuid >> info.sn;
  }
  return hasData;
}

void Publisher::dump()
{
  DPS_PRINT("Publication (outbound)\n");
  for (auto it = cache_->begin(); it != cache_->end(); ++it) {
    DPS_PRINT("  %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
  }
  if (thisSub_) {
    DPS_PRINT("Acknowledgement (inbound)\n");
    for (auto it = thisSub_->cache_->begin(); it != thisSub_->cache_->end(); ++it) {
      DPS_PRINT("  %s(%d)\n", DPS_UUIDToString(DPS_PublicationGetUUID(it->pub_.get())), it->sn_);
    }
  }
}

DPS_Status Publisher::addPublication(TxStream && payload, PublicationInfo * info)
{
  // must check for space before adding the data as DPS_Publish must be called before the
  // copied publication will be correct
  if (!cache_->full()) {
    Range range;
    if (cache_->empty()) {
      range = { sn_ + 1, sn_ + 1 };
    } else {
      range = { cache_->minSN(), sn_ + 1 };
    }
    PublicationHeader header = { QOS_DATA, qos_, range, sn_ + 1 };
    TxStream buf;
    buf << header << payload;
    DPS_Status ret = DPS_Publish(pub_, buf.data(), buf.size(), 0);
    if (ret == DPS_OK) {
      if (info) {
        memcpy(&info->uuid, uuid(), sizeof(DPS_UUID));
        info->sn = header.sn_;
      }
      cache_->addData({ Publication(DPS_CopyPublication(pub_)), header.sn_, std::move(payload) });
      ++sn_;
      resetHeartbeat();
    }
    return ret;
  } else {
    return DPS_ERR_OVERFLOW;
  }
}

void Publisher::onNewPublication(Subscriber * subscriber)
{
  listener_->onNewAcknowledgement(this);
}

TxStream Publisher::heartbeat()
{
  Range range;
  if (cache_->empty()) {
    range = { sn_, sn_ };
  } else {
    range = { cache_->minSN(), cache_->maxSN() };
  }
  PublicationHeader header = { QOS_HEARTBEAT, qos_, range };
  TxStream txBuf;
  txBuf << header;
  return txBuf;
}

void Publisher::resetHeartbeat()
{
  int err = uv_async_send(&async_);
  if (err) {
    DPS_ERRPRINT("uv_async_send failed: %s\n", uv_strerror(err));
  }
}

void Publisher::onAsync_(uv_async_t * handle)
{
  Publisher * publisher = static_cast<Publisher *>(handle->data);
  std::lock_guard<std::recursive_mutex> lock(publisher->internalMutex_);
  publisher->onAsync();
}

void Publisher::onAsync()
{
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

void Publisher::onTimer_(uv_timer_t * handle)
{
  Publisher * publisher = static_cast<Publisher *>(handle->data);
  std::lock_guard<std::recursive_mutex> lock(publisher->internalMutex_);
  publisher->onTimer();
}

void Publisher::onTimer()
{
  if ((heartbeatPolicy_ == HEARTBEAT_ALWAYS) ||
      (heartbeatPolicy_ == HEARTBEAT_UNACKNOWLEDGED && anyUnacked())) {
    // send out a new heartbeat
    TxStream txBuf = heartbeat();
    DPS_Status ret = DPS_Publish(pub_, txBuf.data(), txBuf.size(), 0);
    if (ret != DPS_OK) {
      DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
    }
  } else {
    int err = uv_timer_stop(&timer_);
    if (err) {
      DPS_ERRPRINT("uv_timer_stop failed: %s\n", uv_strerror(err));
    }
  }
}

void Publisher::ackHandler_(DPS_Publication * pub, uint8_t * data, size_t dataLen)
{
  Publisher * publisher = static_cast<Publisher *>(DPS_GetPublicationData(pub));
  RxStream rxBuf(data, dataLen);
  std::lock_guard<std::recursive_mutex> lock(publisher->internalMutex_);
  AckHeader header;
  rxBuf >> header;
  publisher->ackHandler(pub, header, rxBuf);
}

void Publisher::ackHandler(DPS_Publication * pub, const AckHeader & header, RxStream & rxBuf)
{
  DPS_PRINT("ACK %s %d[ ", DPS_UUIDToString(&header.uuid_), header.sns_.base_ - 1);
  for (size_t i = 0; i < header.sns_.size(); ++i) {
    if (header.sns_.test(header.sns_.base_ + i)) {
      DPS_PRINT("%d ", header.sns_.base_ + i);
    }
  }
  DPS_PRINT("]\n");
  resendRequested(pub, header.sns_);
}

bool Publisher::anyUnacked()
{
  return false;
}

void Publisher::resendRequested(DPS_Publication * pub, const SNSet & sns)
{
  // resend nak'd publications
  for (size_t i = 0; i < sns.size(); ++i) {
    uint32_t sn = sns.base_ + i;
    if (sns.test(sn)) {
      auto it = std::find_if(cache_->begin(), cache_->end(), [sn](const Cache<TxStream>::Data & data) {
          return data.sn_ == sn;
        });
      if (it == cache_->end()) {
        // missing publication requested
        continue;
      }
      PublicationHeader header = { QOS_DATA, qos_, { cache_->minSN(), cache_->maxSN() }, it->sn_ };
      TxStream txBuf;
      txBuf << header << it->buf_;
      DPS_Status ret = DPS_Publish(pub, txBuf.data(), txBuf.size(), 0);
      if (ret == DPS_OK) {
        resetHeartbeat();
      } else {
        DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
      }
    }
  }
}

void Publisher::onTimerClose_(uv_handle_t * handle)
{
  Publisher * publisher = static_cast<Publisher *>(handle->data);
  std::lock_guard<std::recursive_mutex> lock(publisher->internalMutex_);
  uv_close((uv_handle_t *)&publisher->async_, onAsyncClose_);
}

void Publisher::onAsyncClose_(uv_handle_t * handle)
{
  Publisher * publisher = static_cast<Publisher *>(handle->data);
  std::lock_guard<std::recursive_mutex> lock(publisher->internalMutex_);
  DPS_SignalEvent(publisher->close_, DPS_OK);
}

ReliablePublisher::ReliablePublisher(const QoS & qos, PublisherListener * listener)
  : Publisher(qos, listener)
{
  heartbeatPolicy_ = HEARTBEAT_ALWAYS;
}

ReliablePublisher::~ReliablePublisher()
{
}

DPS_Status ReliablePublisher::initialize(DPS_Node * node, const std::vector<std::string> & topics)
{
  std::vector<std::string> thisTopic;
  DPS_Status ret;
  std::lock_guard<std::recursive_mutex> lock(internalMutex_);
  ret = Publisher::initialize(node, topics, ackHandler_);
  if (ret != DPS_OK) {
    goto Exit;
  }
  thisSub_ = new ReliablePublisher::Subscriber(qos_, this, uuid());
  thisTopic = { DPS_UUIDToString(uuid()) };
  ret = thisSub_->initialize(node, thisTopic);
  if (ret != DPS_OK) {
    goto Exit;
  }
  resetHeartbeat();
Exit:
  if (ret != DPS_OK) {
    close();
  }
  return ret;
}

DPS_Status ReliablePublisher::publish(TxStream && payload, PublicationInfo * info)
{
  std::lock_guard<std::recursive_mutex> lock(internalMutex_);
  if (cache_->full()) {
    for (auto it = cache_->begin(); it != cache_->end(); ++it) {
      if (ackedByAll(it->sn_)) {
        cache_->removeData(it);
        break;
      }
    }
  }
  return addPublication(std::move(payload), info);
}

void ReliablePublisher::dump()
{
  Publisher::dump();
  DPS_PRINT("Subscriber (reliable)\n");
  for (auto it = remote_.begin(); it != remote_.end(); ++it) {
    DPS_PRINT("  %s %d[ ", DPS_UUIDToString(&it->first), it->second.acked_.base_ - 1);
    for (size_t i = 0; i < it->second.acked_.size(); ++i) {
      if (it->second.acked_.test(it->second.acked_.base_ + i)) {
        DPS_PRINT("%d ", it->second.acked_.base_ + i);
      }
    }
    DPS_PRINT("] alive=%" PRIu64 "\n", it->second.alive_);
  }
}

void ReliablePublisher::ackHandler(DPS_Publication * pub, const AckHeader & header, RxStream & rxBuf)
{
  auto it = remote_.find(header.uuid_);
  if (it != remote_.end()) { // we only care about the state of reliable subscribers
    uint32_t ackSn = header.sns_.base_ - 1;
    it->second.setAcked(ackSn, ackSn);
    it->second.alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub)));
  }
  Publisher::ackHandler(pub, header, rxBuf);
}

bool ReliablePublisher::ackedByAll(uint32_t sn)
{
  // remove dead subscribers
  uint64_t now = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub_)));
  for (auto it = remote_.begin(); it != remote_.end(); ) {
    if (now - it->second.alive_ >= aliveTimeoutMs) {
      it = remote_.erase(it);
    } else {
      ++it;
    }
  }

  // check if the serial number has been acknowledged by all subscribers
  bool acked = true;
  for (auto it = remote_.begin(); acked && it != remote_.end(); ++it) {
    acked = acked && it->second.acked(sn);
  }
  return acked;
}

bool ReliablePublisher::anyUnacked()
{
  for (auto it = cache_->begin(); it != cache_->end(); ++it) {
    if (!ackedByAll(it->sn_)) {
      return true;
    }
  }
  return false;
}

ReliablePublisher::Subscriber::Subscriber(const QoS & qos, ReliablePublisher * publisher, const DPS_UUID * uuid)
  : ReliableSubscriber(qos, publisher, uuid), publisher_(publisher)
{
}

void ReliablePublisher::Subscriber::pubHandler(const DPS_Publication * pub, PublicationHeader & header,
                                               RxStream & rxBuf)
{
  if (!QoSIsCompatible(header.qos_, qos_)) {
    return;
  }

  const DPS_UUID * uuid = DPS_PublicationGetUUID(pub);
  RemoteReliablePublisher & remote = remote_[*uuid];
  remote.range_ = header.range_;

  if (header.type_ == QOS_DATA) {
    DPS_PRINT("DATA %s(%d) [%d,%d]\n", DPS_UUIDToString(uuid), header.sn_, header.range_.first,
              header.range_.second);
    if (publisher_->listener_) {
      if (!remote.received(header.sn_)) {
        // ensure enough space is available in cache to receive
        // missing publications before adding this one
        size_t need = 1;
        for (uint32_t n = header.range_.first; SN_LT(n, header.sn_); ++n) {
          if (!remote.received(n)) {
            ++need;
          }
        }
        if (need <= cache_->avail()) {
          addToCache(pub, header, std::move(rxBuf));
          remote.setReceived(header.sn_, header.range_.first);
        }
      }
      ackPublication(pub);
    }
  } else if (header.type_ == QOS_HEARTBEAT) {
    DPS_PRINT("HEARTBEAT %s [%d,%d]\n", DPS_UUIDToString(uuid), header.range_.first, header.range_.second);
    ackPublication(pub);
  } else if (header.type_ == QOS_ADD) {
    DPS_PRINT("ADD %s [%d,%d]\n", DPS_UUIDToString(uuid), header.range_.first, header.range_.second);
    DPS_UUID subUuid;
    rxBuf >> subUuid;
    Range range;
    if (publisher_->cache_->empty()) {
      range = { publisher_->sn_, publisher_->sn_ };
    } else {
      range = { publisher_->cache_->minSN(), publisher_->cache_->maxSN() };
    }
    // set initial sequence number for the new subscriber
    if (publisher_->remote_.find(subUuid) == publisher_->remote_.end()) {
      if (qos_.durability == DPS_QOS_VOLATILE) {
        publisher_->remote_[subUuid].setAcked(range.second, range.second);
      } else if (qos_.durability == DPS_QOS_TRANSIENT) {
        publisher_->remote_[subUuid].setAcked(range.first - 1, range.first - 1);
      }
    } else {
      // duplicate pub from a new subscriber, the reported range must remain the
      // same as the original so that any publications sent since the new subscriber
      // appeared will get resent
      range.second = publisher_->remote_[subUuid].acked_.base_ - 1;
      if (SN_LT(range.second, range.first)) {
        range.first = range.second;
      }
    }
    TxStream txBuf;
    txBuf << range;
    ackPublication(pub, txBuf);
  }
}
