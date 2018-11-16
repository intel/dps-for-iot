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

inline bool
operator<(const DPS_UUID & a, const DPS_UUID & b)
{
  return DPS_UUIDCompare(&a, &b) < 0;
}

inline bool
operator==(const DPS_UUID & a, const DPS_UUID & b)
{
  return DPS_UUIDCompare(&a, &b) == 0;
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

typedef struct PublicationInfo {
  DPS_UUID uuid;
  uint32_t sn;
} PublicationInfo;

inline TxStream &
operator<<(TxStream & buf, const DPS_UUID & uuid)
{
  return buf.serializeSequence(uuid.val, sizeof(uuid.val));
}

inline RxStream &
operator>>(RxStream & buf, DPS_UUID & uuid)
{
  return buf.deserializeSequence(uuid.val, sizeof(uuid.val));
}

typedef std::pair<uint32_t, uint32_t> Range;

inline TxStream &
operator<<(TxStream & buf, const Range & range)
{
  return buf << range.first << range.second;
}

inline RxStream &
operator>>(RxStream & buf, Range & range)
{
  return buf >> range.first >> range.second;
}

typedef struct PublicationHeader {
  Range range_;
  uint32_t sn_;
} PublicationHeader;

typedef struct SNSet
{
  uint32_t base_;
  std::bitset<64> sn_;        // TODO fix hardcoded size
  bool
  test(uint32_t sn) const
  {
    // TODO need to handle wraparound here with sn < base_
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
  shrink()
  {
    while (sn_.test(0)) {
      sn_ >>= 1;
      ++base_;
    }
  }
  void
  shrink(uint32_t firstSn)
  {
    if (base_ < firstSn) {
      sn_ >>= firstSn - base_;
      base_ = firstSn;
    }
    shrink();
  }
} SNSet;

typedef struct AckHeader
{
  DPS_UUID uuid_;
  SNSet sns_;
} AckHeader;

inline TxStream &
operator<<(TxStream & buf, const AckHeader & header)
{
  buf << header.uuid_ << header.sns_.base_;
  buf.serializeSequence(header.sns_.count());
  for (size_t i = 0; i < header.sns_.size(); ++i) {
    if (header.sns_.test(header.sns_.base_ + i)) {
      buf << header.sns_.base_ + i;
    }
  }
  return buf;
}

inline RxStream &
operator>>(RxStream & buf, AckHeader & header)
{
  buf >> header.uuid_ >> header.sns_.base_;
  size_t size;
  buf.deserializeSequence(&size);
  for (size_t i = 0; i < size; ++i) {
    uint32_t sn;
    buf >> sn;
    header.sns_.set(sn);
  }
  return buf;
}

static const uint8_t QOS_ADD = 1;
static const uint8_t QOS_ACK = 2;

}

#endif
