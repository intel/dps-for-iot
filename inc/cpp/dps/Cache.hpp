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

#ifndef _CACHE_HPP
#define _CACHE_HPP

#include <algorithm>
#include <bitset>
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

typedef std::pair<uint32_t, uint32_t> Range;

typedef struct SNSet
{
    uint32_t base_;
    std::bitset<64> sn_;        // TODO fix hardcoded size
    bool
    test(uint32_t sn) const
    {
      return (sn < base_) || sn_.test(sn - base_);
    }
    SNSet &
    set(uint32_t sn)
    {
      if (base_ <= sn) {
        sn_.set(sn - base_);
      }
      return *this;
    }
    std::size_t
    count() const
    {
      return sn_.count();
    }
    bool
    any() const
    {
      return sn_.any();
    }
    std::size_t
    size() const
    {
      return sn_.size();
    }
    void
    shrink(uint32_t firstSN)
    {
      if (base_ < firstSN) {
        sn_ >>= firstSN - base_;
        base_ = firstSN;
      }
      while (sn_.test(0)) {
        sn_ >>= 1;
        ++base_;
      }
    }
} SNSet;

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

  typename std::deque<Data>::const_iterator
  begin() const
  {
    return data_.begin();
  }

  typename std::deque<Data>::const_iterator
  end() const
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

  const Data &
  front() const
  {
    return data_.front();
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

  void
  removeData(typename std::deque<Data>::const_iterator pos)
  {
    data_.erase(pos);
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
  takeNextData(Publication & pub, uint32_t & sn, Stream & buffer)
  {
    if (empty()) {
      return false;
    }
    Cache::Data & data = data_.front();
    pub = std::move(data.pub_);
    sn = data.sn_;
    buffer = std::move(data.buf_);
    data_.pop_front();
    return true;
  }

private:
  size_t depth_;
  std::deque<Data> data_;
};

}

#endif
