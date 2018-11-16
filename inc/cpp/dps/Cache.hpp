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

#ifndef _DPS_CACHE_HPP
#define _DPS_CACHE_HPP

#include <algorithm>
#include <deque>
#include <memory>

#include <dps/dps.h>
#include <dps/CborStream.hpp>

namespace dps
{

struct PublicationDeleter {
  void operator()(DPS_Publication * pub) { DPS_DestroyPublication(pub); }
};

typedef std::unique_ptr<DPS_Publication, PublicationDeleter> Publication;

template <typename Stream>
class Cache
{
public:
  typedef struct Data
  {
    Publication pub_;
    uint32_t sn_;
    Stream buf_;
  } Data;

  explicit Cache(size_t depth)
  : depth_(depth)
  {
  }

  typename std::deque<Data>::iterator
  begin()
  {
    return data_.begin();
  }

  typename std::deque<Data>::iterator
  end()
  {
    return data_.end();
  }

  bool
  empty() const
  {
    return data_.empty();
  }

  size_t
  size() const
  {
    return data_.size();
  }

  size_t
  capacity() const
  {
    return depth_;
  }

  bool
  full() const
  {
    return size() >= capacity();
  }
  size_t
  avail() const
  {
    return capacity() - size();
  }

  const Data &
  front() const
  {
    return data_.front();
  }
  const Data &
  back() const
  {
    return data_.back();
  }

  uint32_t
  minSN() const
  {
    return data_.front().sn_;
  }

  uint32_t
  maxSN() const
  {
    return data_.back().sn_;
  }

  typename std::deque<Data>::iterator
  removeData(typename std::deque<Data>::iterator pos)
  {
    return data_.erase(pos);
  }

  bool
  addData(Data && data)
  {
    if (full()) {
      return false;
    }
    data_.push_back(std::move(data));
    std::sort(data_.begin(), data_.end(), [](const Data & a, const Data & b) { return a.sn_ < b.sn_; });
    return true;
  }

  bool
  takeNextData(Data & data)
  {
    if (empty()) {
      return false;
    }
    data.pub_ = std::move(data_.front().pub_);
    data.sn_ = data_.front().sn_;
    data.buf_ = std::move(data_.front().buf_);
    data_.pop_front();
    return true;
  }

private:
  size_t depth_;
  std::deque<Data> data_;
};

}

#endif
