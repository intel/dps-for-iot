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

#include <algorithm>
#include <numeric>
#include <dps/dps.h>
#include <dps/private/loop.h>
#include <dps/Node.hpp>
#include <dps/Publisher.hpp>
#include <dps/Subscriber.hpp>

using namespace dps;

DPS_Status DPS_UUIDFromString(const char * str, DPS_UUID * uuid)
{
  size_t n;
  uint8_t * dst = uuid->val;
  const char * src = str;
  size_t i, j;

  if (!str || ((n = strlen(str)) < 36)) {
    return DPS_ERR_INVALID;
  }
  for (i = 0; i < sizeof(uuid->val); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      if (*src++ != '-') {
        return DPS_ERR_INVALID;
      }
    }
    for (j = 0; j < 2; ++j) {
      if ('0' <= *src && *src <= '9') {
        dst[i] = (dst[i] << 4) | (*src++ - '0');
      } else if ('a' <= *src && *src <= 'f') {
        dst[i] = (dst[i] << 4) | (*src++ - 'a' + 10);
      } else {
        return DPS_ERR_INVALID;
      }
    }
  }
  return DPS_OK;
}

static DPS_Status UUIDFromPublication(const DPS_Publication * pub, DPS_UUID * uuid)
{
  for (size_t i = 0; i < DPS_PublicationGetNumTopics(pub); ++i) {
    const char * topic = DPS_PublicationGetTopic(pub, i);
    if (strncmp(topic, "$ROS:uuid:", sizeof("$ROS:uuid:") - 1) == 0) {
      const char * str = topic + sizeof("$ROS:uuid:") - 1;
      return DPS_UUIDFromString(str, uuid);
    }
  }
  return DPS_ERR_MISSING;
}

RemoteNode::RemoteNode()
  : name_(nullptr), namespace_(nullptr), pub_(nullptr)
{
}

bool RemoteNode::update(const DPS_UUID * uuid, const DPS_Publication * pub)
{
  pub_ = Publication(DPS_CopyPublication(pub));
  memcpy(&uuid_, uuid, sizeof(DPS_UUID));
  std::map<std::string, size_t> subscriber;
  std::map<std::string, size_t> publisher;
  name_ = "";
  namespace_ = "";
  for (size_t i = 0; i < DPS_PublicationGetNumTopics(pub_.get()); ++i) {
    const char * topic = DPS_PublicationGetTopic(pub_.get(), i);
    if (strncmp(topic, "$ROS:name:", sizeof("$ROS:name:") - 1) == 0) {
      name_ = topic + sizeof("$ROS:name:") - 1;
    } else if (strncmp(topic, "$ROS:namespace:", sizeof("$ROS:namespace:") - 1) == 0) {
      namespace_ = topic + sizeof("$ROS:namespace:") - 1;
    } else if (addSubscriber(topic, subscriber) || addPublisher(topic, publisher)) {
      // nothing else to do with this topic
    }
  }
  bool notify = (subscriber != subscriber_) || (publisher != publisher_);
  subscriber_ = subscriber;
  publisher_ = publisher;
  return notify;
}

bool RemoteNode::addSubscriber(const char * topic, std::map<std::string, size_t> & subscriber)
{
  return add(topic, "$ROS:subscriber:", subscriber);
}

bool RemoteNode::addPublisher(const char * topic, std::map<std::string, size_t> & publisher)
{
  return add(topic, "$ROS:publisher:", publisher);
}

bool RemoteNode::add(const char * topic, const char * prefix, std::map<std::string, size_t> & count)
{
  size_t n = strlen(prefix);
  if (strncmp(topic, prefix, n) != 0) {
    return false;
  }
  const char * uuid = topic + n;
  const char * topic_ = strstr(uuid, ":");
  if (!topic_) {
    return false;
  }
  ++topic_;
  const char * separator = strstr(topic_, ":");
  if (separator) {
    // ignore topics with extra segments (i.e. qos info) after the
    // application topic, we only want the application topic here
    return false;
  }
  ++count[std::string(topic_)];
  return true;
}

Node::Node(size_t domainId, const char * ns, const char * name, NodeListener * listener)
  : domainId_(domainId), namespace_(ns), name_(name), listener_(listener), node_(nullptr), pub_(nullptr), close_(nullptr)
{
  DPS_InitUUID();
  DPS_GenerateUUID(&uuid_);
}

Node::~Node()
{
}

DPS_Status Node::initialize(int mcast, int listenPort)
{
  std::string topic;
  const char * ctopic;
  DPS_Status ret = DPS_OK;
  int err;
  // ':' is not a valid separator for application-layer topics, it is used only for internal topics
  node_ = DPS_CreateNode("/:", nullptr, nullptr);
  if (!node_) {
    ret = DPS_ERR_RESOURCES;
    goto Exit;
  }
  ret = DPS_StartNode(node_, mcast, listenPort);
  if (ret != DPS_OK) {
    goto Exit;
  }
  topic = std::string("$ROS:domain:") + std::to_string(domainId_);
  ctopic = topic.c_str();
  sub_ = DPS_CreateSubscription(node_, &ctopic, 1);
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
  err = uv_async_init(DPS_GetLoop(node_), &async_, onAsync_);
  if (err) {
    return DPS_ERR_FAILURE;
  }
  async_.data = this;
  err = uv_timer_init(DPS_GetLoop(node_), &timer_);
  if (err) {
    return DPS_ERR_FAILURE;
  }
  timer_.data = this;
  if (pub_ || sub_) {
    resetHeartbeat();
  }
Exit:
  if (ret != DPS_OK) {
    close();
  }
  return ret;
}

void Node::onNodeDestroyed_(DPS_Node* node, void* data)
{
  DPS_Event* event = (DPS_Event*)data;
  DPS_SignalEvent(event, DPS_OK);
}

DPS_Status Node::close()
{
  if (!node_) {
    return DPS_OK;
  }

  DPS_Event * event;
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
  if (pub_) {
    ret = DPS_DestroyPublication(pub_);
    if (ret != DPS_OK) {
      goto Exit;
    }
    pub_ = nullptr;
  }
  ret = DPS_DestroyNode(node_, onNodeDestroyed_, event);
  if (ret != DPS_OK) {
    goto Exit;
  }
  ret = DPS_WaitForEvent(event);
Exit:
  DPS_DestroyEvent(event);
  return ret;
}

DPS_Status Node::advertise()
{
  std::vector<std::string> topics;
  topics.push_back(std::string("$ROS:domain:") + std::to_string(domainId_));
  topics.push_back(std::string("$ROS:uuid:") + DPS_UUIDToString(&uuid_));
  if (!name_.empty()) {
    topics.push_back(std::string("$ROS:name:") + name_);
  }
  if (!namespace_.empty()) {
    topics.push_back(std::string("$ROS:namespace:") + namespace_);
  }
  for (auto it = publisher_.begin(); it != publisher_.end(); ++it) {
    auto ts = (*it)->topics();
    for (auto t = ts.begin(); t != ts.end(); ++t) {
      std::string topic = std::string("$ROS:publisher:") + DPS_UUIDToString((*it)->uuid()) + ":" + *t;
      topics.push_back(topic);
      if ((*it)->qos().reliability == DPS_QOS_RELIABLE) { // TODO don't need others currently
        topics.push_back(topic + ":qos:reliable");
      }
    }
  }
  for (auto it = subscriber_.begin(); it != subscriber_.end(); ++it) {
    auto ts = (*it)->topics();
    for (auto t = ts.begin(); t != ts.end(); ++t) {
      std::string topic = std::string("$ROS:subscriber:") + DPS_UUIDToString((*it)->uuid()) + ":" + *t;
      topics.push_back(topic);
      if ((*it)->qos().reliability == DPS_QOS_RELIABLE) { // TODO don't need others currently
        topics.push_back(topic + ":qos:reliable");
      }
    }
  }
  return advertise(topics);
}

DPS_Status Node::advertise(const std::vector<std::string> & topics)
{
  if (pub_) {
    DPS_DestroyPublication(pub_);
  }
  pub_ = DPS_CreatePublication(node_);
  if (!pub_) {
    return DPS_ERR_RESOURCES;
  }
  std::vector<const char *> ctopics;
  std::transform(topics.begin(), topics.end(), std::back_inserter(ctopics),
                 [](const std::string & s) { return s.c_str(); });
  DPS_Status ret = DPS_InitPublication(pub_, ctopics.data(), ctopics.size(), DPS_FALSE, nullptr, nullptr);
  if (ret != DPS_OK) {
    return ret;
  }
  resetHeartbeat();
  return DPS_OK;
}

void Node::add(Publisher * publisher)
{
  publisher_.push_back(publisher);
}

void Node::remove(Publisher * publisher)
{
  publisher_.remove(publisher);
}

void Node::add(Subscriber * subscriber)
{
  subscriber_.push_back(subscriber);
}

void Node::remove(Subscriber * subscriber)
{
  subscriber_.remove(subscriber);
}

void Node::pubHandler_(DPS_Subscription * sub, const DPS_Publication * pub, uint8_t * payload, size_t len)
{
  Node * node = static_cast<Node *>(DPS_GetSubscriptionData(sub));
  node->pubHandler(pub, payload, len);
}

void Node::pubHandler(const DPS_Publication * pub, uint8_t * payload, size_t len)
{
  DPS_UUID uuid;
  DPS_Status ret = UUIDFromPublication(pub, &uuid);
  if (ret != DPS_OK) {
    return;
  }
  bool notify = remote_[uuid].update(&uuid, pub);
  remote_[uuid].alive_ = uv_now(DPS_GetLoop(DPS_PublicationGetNode(pub)));
  if (notify && listener_) {
    listener_->onNewChange(this, &remote_[uuid]);
  }
}

std::vector<const RemoteNode *> Node::discovered() const
{
  // TODO need the mutex here
  std::vector<const RemoteNode *> remotes;
  std::transform(remote_.begin(), remote_.end(), std::back_inserter(remotes),
                 [](const std::pair<const DPS_UUID, RemoteNode> & r) { return &r.second; });
  return remotes;
}

size_t Node::publisherCount(const char * topic) const
{
  return std::accumulate(remote_.begin(), remote_.end(), 0,
                         [topic](size_t count, const std::pair<const DPS_UUID, RemoteNode> & r) {
                           auto it = r.second.publisher_.find(topic);
                           return it == r.second.publisher_.end() ? count : count + it->second;
                         });
}

size_t Node::subscriberCount(const char * topic) const
{
  return std::accumulate(remote_.begin(), remote_.end(), 0,
                         [topic](size_t count, const std::pair<const DPS_UUID, RemoteNode> & r) {
                           auto it = r.second.subscriber_.find(topic);
                           return it == r.second.subscriber_.end() ? count : count + it->second;
                         });
}

void Node::resetHeartbeat()
{
  int err = uv_async_send(&async_);
  if (err) {
    DPS_ERRPRINT("uv_async_send failed: %s\n", uv_strerror(err));
  }
}

void Node::onAsync_(uv_async_t * handle)
{
  Node * node = static_cast<Node *>(handle->data);
  node->onAsync();
}

void Node::onAsync()
{
  // close all the open handles
  if (close_) {
    uv_close((uv_handle_t *)&timer_, onTimerClose_);
    return;
  }
  // start timer
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

void Node::onTimer_(uv_timer_t * handle)
{
  Node * node = static_cast<Node *>(handle->data);
  node->onTimer();
}

void Node::onTimer()
{
  // remove dead nodes
  if (sub_) {
    uint64_t now = uv_now(DPS_GetLoop(DPS_SubscriptionGetNode(sub_)));
    for (auto it = remote_.begin(); it != remote_.end(); ) {
      if (now - it->second.alive_ >= aliveTimeoutMs) {
        if (listener_ && (!it->second.subscriber_.empty() || !it->second.publisher_.empty())) {
          listener_->onNewChange(this, &it->second);
        }
        it = remote_.erase(it);
      } else {
        ++it;
      }
    }
  }
  // publish the advertisement
  if (pub_) {
    DPS_Status ret = DPS_Publish(pub_, nullptr, 0, 0, nullptr);
    if (ret != DPS_OK) {
      DPS_ERRPRINT("Publish failed: %s\n", DPS_ErrTxt(ret));
    }
  }
}

void Node::onTimerClose_(uv_handle_t * handle)
{
  Node * node = static_cast<Node *>(handle->data);
  uv_close((uv_handle_t *)&node->async_, onAsyncClose_);
}

void Node::onAsyncClose_(uv_handle_t * handle)
{
  Node * node = static_cast<Node *>(handle->data);
  DPS_SignalEvent(node->close_, DPS_OK);
}
