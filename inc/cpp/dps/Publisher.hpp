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
  virtual DPS_Status initialize(DPS_Node * node, const std::vector<std::string> & topics);
  virtual DPS_Status close();
  virtual DPS_Status publish(TxStream && payload, PublicationInfo * info = nullptr);
  const DPS_UUID * uuid() const;
  size_t unreadCount();
  bool takeNextData(RxStream & buf, PublicationInfo & info);
  virtual void dump();

protected:
  std::recursive_mutex internalMutex_;
  QoS qos_;
  PublisherListener * listener_;
  DPS_Publication * pub_;
  uint32_t sn_;
  Cache<TxStream> * cache_;
  Subscriber * thisSub_;

  DPS_Status initialize(DPS_Node * node, const std::vector<std::string> & topics,
                        DPS_AcknowledgementHandler handler);
  DPS_Status addPublication(TxStream && payload, PublicationInfo * info = nullptr);
  virtual void onNewPublication(Subscriber * subscriber);
};

class ReliablePublisher : public Publisher
{
public:
  ReliablePublisher(const QoS & qos, PublisherListener * listener);
  virtual ~ReliablePublisher();
  virtual DPS_Status initialize(DPS_Node * node, const std::vector<std::string> & topics);
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

  static const uint64_t heartbeatPeriodMs = 1000;
  static const uint64_t aliveTimeoutMs = 4000;

  enum {
    HEARTBEAT_ALWAYS,
    HEARTBEAT_UNACKNOWLEDGED
  } heartbeatPolicy_;
  uv_async_t async_;
  uv_timer_t timer_;
  DPS_Event * close_;
  std::map<DPS_UUID, RemoteSubscriber> remote_;

  static void ackHandler_(DPS_Publication * pub, uint8_t * data, size_t dataLen);
  virtual void ackHandler(DPS_Publication * pub, const AckHeader & header, RxStream & rxBuf);
  bool ackedByAll(uint32_t sn);
  bool anyUnacked();
  void resendRequested(DPS_Publication * pub, const SNSet & sns);
  virtual TxStream heartbeat();
  void resetHeartbeat();
  static void onAsync_(uv_async_t * handle);
  void onAsync();
  static void onTimer_(uv_timer_t * handle);
  void onTimer();
  static void onTimerClose_(uv_handle_t * handle);
  static void onAsyncClose_(uv_handle_t * handle);
};

}

#endif
