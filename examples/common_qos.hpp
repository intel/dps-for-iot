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

#ifndef _COMMON_QOS_HPP
#define _COMMON_QOS_HPP

#include <dps/CborStream.hpp>

/**
 * Controls whether sending a publication is best-effort or a resend is attempted if a publication
 * is detected as missing.
 */
typedef enum {
    DPS_QOS_BEST_EFFORT = 0,    /**< Best-effort reliability */
    DPS_QOS_RELIABLE = 1        /**< Resend missed publications */
} DPS_QoSReliability;

inline bool operator<(const DPS_UUID& a, const DPS_UUID& b)
{
  return DPS_UUIDCompare(&a, &b) < 0;
}

inline dps::TxStream& operator<<(dps::TxStream& buf, const DPS_UUID& uuid)
{
    return buf.serializeSequence(uuid.val, sizeof(uuid.val));
}

inline dps::RxStream& operator>>(dps::RxStream& buf, DPS_UUID& uuid)
{
    return buf.deserializeSequence(uuid.val, sizeof(uuid.val));
}

inline dps::TxStream& operator<<(dps::TxStream& buf, const dps::Range& range)
{
    return buf << range.first << range.second;
}

inline dps::RxStream& operator>>(dps::RxStream& buf, dps::Range& range)
{
    return buf >> range.first >> range.second;
}

typedef struct _Ack {
    DPS_UUID uuid_;
    dps::SNSet set_;
} Ack;

inline dps::TxStream& operator<<(dps::TxStream& buf, const Ack& ack)
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

inline dps::RxStream& operator>>(dps::RxStream& buf, Ack& ack)
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

#endif
