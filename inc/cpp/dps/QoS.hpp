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

#ifndef _DPS_QOS_HPP
#define _DPS_QOS_HPP

#include <bitset>
#include <dps/dps.h>
#include <dps/CborStream.hpp>

inline bool operator<(const DPS_UUID & a, const DPS_UUID & b)
{
  return DPS_UUIDCompare(&a, &b) < 0;
}

namespace dps
{

typedef enum {
    DPS_QOS_BEST_EFFORT = 0,    /**< Best-effort reliability */
    DPS_QOS_RELIABLE = 1        /**< Resend missed publications */
} QoSReliability;

typedef struct QoS
{
  size_t depth;
  QoSReliability reliability;
} QoS;

inline TxStream & operator<<(TxStream & buf, const DPS_UUID & uuid)
{
  return buf.serializeSequence(uuid.val, sizeof(uuid.val));
}

inline RxStream & operator>>(RxStream & buf, DPS_UUID & uuid)
{
  return buf.deserializeSequence(uuid.val, sizeof(uuid.val));
}

typedef std::pair<uint32_t, uint32_t> Range;

inline TxStream & operator<<(TxStream & buf, const Range & range)
{
  return buf << range.first << range.second;
}

inline RxStream & operator>>(RxStream & buf, Range & range)
{
  return buf >> range.first >> range.second;
}

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

typedef struct Ack
{
  DPS_UUID uuid_;
  SNSet set_;
} Ack;

inline TxStream & operator<<(TxStream & buf, const Ack & ack)
{
  buf << ack.uuid_ << ack.set_.base_;
  buf.serializeSequence(ack.set_.count());
  for (size_t i = 0; i < ack.set_.size(); ++i) {
    if (ack.set_.test(ack.set_.base_ + i)) {
      buf << ack.set_.base_ + i;
    }
  }
  return buf;
}

inline RxStream & operator>>(RxStream & buf, Ack & ack)
{
  buf >> ack.uuid_ >> ack.set_.base_;
  size_t size;
  buf.deserializeSequence(&size);
  for (size_t i = 0; i < size; ++i) {
    uint32_t sn;
    buf >> sn;
    ack.set_.set(sn);
  }
  return buf;
}

}

#endif
