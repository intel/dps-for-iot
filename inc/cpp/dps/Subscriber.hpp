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
#include <mutex>
#include <dps/dbg.h>
#include <dps/Cache.hpp>
#include <dps/Publisher.hpp>
#include <dps/PublisherListener.hpp>
#include <dps/QoS.hpp>

namespace dps
{

class SubscriberListener;

class Subscriber
{
  friend class Publisher;
public:
  Subscriber(const QoS & qos, SubscriberListener * listener);
  Subscriber(const QoS & qos, SubscriberListener * listener, const DPS_UUID * uuid);
  virtual ~Subscriber();
  DPS_Subscription * get() { return sub_; }
  const QoS & qos() const { return qos_; }
  std::vector<std::string> topics() const;
  virtual DPS_Status initialize(Node * node, const std::vector<std::string> & topics);
  virtual DPS_Status close();
  const DPS_UUID * uuid() const;
  DPS_Status setDiscoverable(bool discoverable);
  size_t unreadCount();
  bool takeNextData(RxStream & buf, PublicationInfo & info);
  virtual DPS_Status ack(TxStream && payload, const DPS_UUID * uuid, uint32_t sn);
  virtual void dump();

protected:
  class RemotePublisher
  {
  public:
    Publisher * pub_;
    DPS_Status initialize(const DPS_UUID * uuid, Subscriber * subscriber);
  };

  std::recursive_mutex internalMutex_;
  QoS qos_;
  SubscriberListener * listener_;
  Node * node_;
  DPS_Subscription * sub_;
  Cache<RxStream> * cache_;
  DPS_UUID uuid_;
  std::map<DPS_UUID, RemotePublisher> remote_;

  static void pubHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * data, size_t dataLen);
  virtual void pubHandler(const DPS_Publication * pub, PublicationHeader & header, RxStream & rxBuf);
  void addToCache(const DPS_Publication * pub, const PublicationHeader & header, RxStream && buf);
  void takeFromCache(RxStream & buf, PublicationInfo & info);
};

class ReliableSubscriber : public Subscriber
{
public:
  ReliableSubscriber(const QoS & qos, SubscriberListener * listener);
  ReliableSubscriber(const QoS & qos, SubscriberListener * listener, const DPS_UUID * uuid);
  virtual ~ReliableSubscriber();
  virtual DPS_Status close();
  virtual DPS_Status ack(TxStream && payload, const DPS_UUID * uuid, uint32_t sn);
  virtual void dump();

protected:
  class Publisher;
  class RemoteReliablePublisher
  {
  public:
    Range range_;
    SNSet received_;
    Publisher * pub_;
    bool busy_;
    void
    setReceived(uint32_t sn, uint32_t firstSN)
    {
      if (received_.base_ == 0) {
        received_.base_ = firstSN;
      }
      received_.set(sn).shrink(firstSN);
    }
    bool
    received(uint32_t sn) const
    {
      return received_.test(sn);
    }
    DPS_Status initialize(const DPS_UUID * uuid, ReliableSubscriber * subscriber);
  };

  std::map<DPS_UUID, RemoteReliablePublisher> remote_;

  virtual void pubHandler(const DPS_Publication * pub, PublicationHeader & header, RxStream & rxBuf);
  void ackPublication(const DPS_Publication * pub, const TxStream & payload);
  void ackPublication(const DPS_Publication * pub);
  SNSet missing(const DPS_UUID * uuid, size_t avail);
};

}

#endif
