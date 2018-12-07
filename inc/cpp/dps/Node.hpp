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

#ifndef _DPS_NODE_HPP
#define _DPS_NODE_HPP

#include <list>
#include <map>
#include <string>
#include <uv.h>
#include <vector>
#include <dps/dps.h>
#include <dps/event.h>
#include <dps/Cache.hpp>

DPS_Status DPS_UUIDFromString(const char * str, DPS_UUID * uuid);

namespace dps
{

class Publisher;
class Subscriber;

class Node;

class RemoteNode
{
public:
  DPS_UUID uuid_;
  const char * name_;
  const char * namespace_;
  std::map<std::string, size_t> subscriber_;
  std::map<std::string, size_t> publisher_;
  uint64_t alive_;

  RemoteNode();
  bool update(const DPS_UUID * uuid, const DPS_Publication * pub);
private:
  Publication pub_;

  bool addSubscriber(const char * topic, std::map<std::string, size_t> & subscriber);
  bool addPublisher(const char * topic, std::map<std::string, size_t> & publisher);
  bool add(const char * topic, const char * prefix, std::map<std::string, size_t> & count);
};

class NodeListener
{
public:
  virtual ~NodeListener() {};
  virtual void onNewChange(Node * node, const RemoteNode * remote) = 0;
};

class Node
{
public:
  Node(size_t domainId, const char * namespace_, const char * name, NodeListener * listener);
  ~Node();
  DPS_Node * get() { return node_; }
  DPS_Status initialize(int mcast, int listenPort);
  DPS_Status close();

  DPS_Status advertise();
  void add(Publisher * publisher);
  void remove(Publisher * publisher);
  void add(Subscriber * subscriber);
  void remove(Subscriber * subscriber);

  // TODO DPS_Status discover();
  std::vector<const RemoteNode *> discovered() const;
  size_t publisherCount(const char * topic) const;
  size_t subscriberCount(const char * topic) const;

private:
  static const uint64_t heartbeatPeriodMs = 1000;
  static const uint64_t aliveTimeoutMs = 4000;

  DPS_Node * node_;
  size_t domainId_;
  std::string namespace_;
  std::string name_;
  NodeListener * listener_;
  DPS_UUID uuid_;
  DPS_Publication * pub_;
  std::list<Publisher *> publisher_;
  std::list<Subscriber *> subscriber_;
  DPS_Subscription * sub_;
  uv_async_t async_;
  uv_timer_t timer_;
  DPS_Event * close_;
  std::map<DPS_UUID, RemoteNode> remote_;

  static void onNodeDestroyed_(DPS_Node * node, void * data);
  DPS_Status advertise(const std::vector<std::string> & topics);
  static void pubHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * payload, size_t len);
  void pubHandler(const DPS_Publication * pub, uint8_t * payload, size_t len);
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
