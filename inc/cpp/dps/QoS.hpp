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
  DPS_QOS_VOLATILE = 0, /**< Do not send old publications to new subscribers */
  DPS_QOS_TRANSIENT = 1 /**< Send old publications to new subscribers */
} QoSDurability;

typedef enum {
  DPS_QOS_BEST_EFFORT = 0, /**< Best-effort reliability */
  DPS_QOS_RELIABLE = 1     /**< Resend missed publications */
} QoSReliability;

typedef struct QoS
{
  size_t depth;
  QoSDurability durability;
  QoSReliability reliability;
} QoS;

inline bool
QoSIsCompatible(QoS & request, QoS & offer)
{
  return (request.durability <= offer.durability) && (request.reliability <= offer.reliability);
}

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

static const uint8_t QOS_DATA = 1;
static const uint8_t QOS_HEARTBEAT = 2;
static const uint8_t QOS_ADD = 3;

typedef struct PublicationHeader {
  uint8_t type_;
  QoS qos_;
  Range range_;
  uint32_t sn_;
} PublicationHeader;

inline TxStream &
operator<<(TxStream & buf, const PublicationHeader & header)
{
  buf << header.type_ << header.qos_.durability << header.qos_.reliability << header.range_;
  if (header.type_ == QOS_DATA) {
    buf << header.sn_;
  }
  return buf;
}

inline RxStream &
operator>>(RxStream & buf, PublicationHeader & header)
{
  uint8_t durability, reliability;
  buf >> header.type_ >> durability >> reliability >> header.range_;
  header.qos_.durability = static_cast<QoSDurability>(durability);
  header.qos_.reliability = static_cast<QoSReliability>(reliability);
  if (header.type_ == QOS_DATA) {
    buf >> header.sn_;
  }
  return buf;
}

inline bool
SN_LT(uint32_t a, uint32_t b)
{
  return ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0);
}

inline bool
SN_LE(uint32_t a, uint32_t b)
{
  return ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0);
}

typedef struct SNSet
{
  uint32_t base_;
  std::vector<bool> sn_;
  bool
  test(uint32_t sn) const
  {
    if (SN_LT(sn, base_)) {
      return true;
    } else if (sn - base_ < sn_.size()) {
      return sn_[sn - base_];
    } else {
      return false;
    }
  }
  SNSet &
  set(uint32_t sn)
  {
    if (SN_LT(sn, base_)) {
      // nothing to do
    } else if (sn - base_ < sn_.size()) {
      sn_[sn - base_] = true;
    } else {
      sn_.resize((sn - base_) + 1);
      sn_[sn - base_] = true;
    }
    return *this;
  }
  size_t
  count() const
  {
    size_t n = 0;
    for (size_t i = 0; i < sn_.size(); ++i) {
      if (sn_[i]) {
        ++n;
      }
    }
    return n;
  }
  size_t
  size() const
  {
    return sn_.size();
  }
  void
  shrink()
  {
    while (!sn_.empty() && sn_[0]) {
      sn_.erase(sn_.begin());
      ++base_;
    }
  }
  void
  shrink(uint32_t firstSn)
  {
    while (SN_LT(base_, firstSn)) {
      if (!sn_.empty()) {
        sn_.erase(sn_.begin());
      }
      ++base_;
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

}

#endif
