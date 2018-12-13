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

#include <map>
#include <mutex>
#include <uv.h>
#include <dps/event.h>
#include <dps/Cache.hpp>
#include <dps/Node.hpp>
#include <dps/QoS.hpp>
#include <dps/Subscriber.hpp>
#include <dps/SubscriberListener.hpp>

namespace dps
{

class PublisherListener;
class Subscriber;

class Publisher : protected SubscriberListener
{
  friend class Subscriber;
  friend class ReliableSubscriber;
public:
  Publisher(const QoS & qos, PublisherListener * listener);
  virtual ~Publisher();
  DPS_Publication * get() { return pub_; }
  const QoS & qos() const { return qos_; }
  std::vector<std::string> topics() const;
  virtual DPS_Status initialize(Node * node, const std::vector<std::string> & topics);
  virtual DPS_Status close();
  DPS_Status setDiscoverable(bool discoverable);
  virtual DPS_Status publish(TxStream && payload, PublicationInfo * info = nullptr);
  const DPS_UUID * uuid() const;
  size_t unreadCount();
  bool takeNextData(RxStream & buf, PublicationInfo & info);
  virtual void dump();

protected:
  static const uint64_t heartbeatPeriodMs = 1000;

  std::recursive_mutex internalMutex_;
  QoS qos_;
  PublisherListener * listener_;
  Node * node_;
  DPS_Publication * pub_;
  uint32_t sn_;
  Cache<TxStream> * cache_;
  enum {
    PUBLISH_IDLE,
    PUBLISH_BUSY
  } publishState_;
  Subscriber * thisSub_;
  enum {
    HEARTBEAT_NEVER,
    HEARTBEAT_ALWAYS,
    HEARTBEAT_UNACKNOWLEDGED
  } heartbeatPolicy_;
  uv_async_t async_;
  uv_timer_t timer_;
  DPS_Event * close_;

  DPS_Status initialize(Node * node, const std::vector<std::string> & topics,
                        DPS_AcknowledgementHandler handler);
  DPS_Status addPublication(TxStream && payload, PublicationInfo * info = nullptr);
  virtual void onNewPublication(Subscriber * subscriber);
  virtual TxStream heartbeat();
  void resetHeartbeat();
  static void onAsync_(uv_async_t * handle);
  void onAsync();
  static void onTimer_(uv_timer_t * handle);
  void onTimer();
  static void onTimerClose_(uv_handle_t * handle);
  static void onAsyncClose_(uv_handle_t * handle);
  static void ackHandler_(DPS_Publication * pub, uint8_t * data, size_t dataLen);
  virtual void ackHandler(DPS_Publication * pub, const AckHeader & header, RxStream & rxBuf);
  virtual bool anyUnacked();
  void publish();
  void republishRequested(DPS_Publication * pub, const SNSet & sns);
  static void onPublishComplete_(DPS_Publication* pub, DPS_Status status);
  void onPublishComplete(DPS_Publication* pub, DPS_Status status);
};

class ReliablePublisher : public Publisher
{
public:
  ReliablePublisher(const QoS & qos, PublisherListener * listener);
  virtual ~ReliablePublisher();
  virtual DPS_Status initialize(Node * node, const std::vector<std::string> & topics);
  virtual DPS_Status close();
  virtual DPS_Status publish(TxStream && payload, PublicationInfo * info = nullptr);
  virtual void dump();

protected:
  class Subscriber;
  class RemoteSubscriber
  {
  public:
    SNSet acked_;
    uint64_t alive_;

    void
    setAcked(uint32_t sn, uint32_t firstSn)
    {
      if (acked_.base_ == 0) {
        acked_.base_ = firstSn;
      }
      acked_.set(sn).shrink(firstSn);
    }
    bool
    acked(uint32_t sn) const
    {
      return acked_.test(sn);
    }
  };

  static const uint64_t aliveTimeoutMs = 4000;

  std::vector<DPS_Subscription *> advertisementSub_;
  std::map<DPS_UUID, RemoteSubscriber> remote_;

  virtual void ackHandler(DPS_Publication * pub, const AckHeader & header, RxStream & rxBuf);
  bool ackedByAll(uint32_t sn);
  virtual bool anyUnacked();
  static void advertisementHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * data, size_t dataLen);
  virtual void advertisementHandler(const DPS_Publication * pub);
};

}

#endif
