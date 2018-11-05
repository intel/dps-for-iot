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

#ifndef _CBORSTREAM_HPP
#define _CBORSTREAM_HPP

#include <stdexcept>
#include <string>
#include <vector>

#include <dps/private/cbor.h>

namespace dps
{

class TxStream
{
public:
  TxStream(size_t hint = 1024)
  {
    ret_ = DPS_OK;
    size_ = 0;
    if (DPS_TxBufferInit(&buffer_, NULL, hint) != DPS_OK) {
      throw std::bad_alloc();
    }
  }
  ~TxStream()
  {
    DPS_TxBufferFree(&buffer_);
  }
  TxStream(const TxStream& other)
  {
    ret_ = other.ret_;
    size_ = other.size_;
    if (DPS_TxBufferInit(&buffer_, NULL, DPS_TxBufferCapacity(&other.buffer_)) != DPS_OK) {
      throw std::bad_alloc();
    }
    DPS_TxBufferAppend(&buffer_, other.buffer_.base, DPS_TxBufferUsed(&other.buffer_));
  }
  TxStream(TxStream&& other)
  {
    ret_ = other.ret_;
    size_ = other.size_;
    buffer_.base = other.buffer_.base;
    buffer_.eob = other.buffer_.eob;
    buffer_.txPos = other.buffer_.txPos;
    other.size_ = 0;
    DPS_TxBufferClear(&other.buffer_);
  }
  TxStream& operator=(const TxStream& other)
  {
    if (this != &other) {
      DPS_TxBufferFree(&buffer_);
      ret_ = other.ret_;
      size_ = other.size_;
      if (DPS_TxBufferInit(&buffer_, NULL, DPS_TxBufferCapacity(&other.buffer_)) != DPS_OK) {
        throw std::bad_alloc();
      }
      DPS_TxBufferAppend(&buffer_, other.buffer_.base, DPS_TxBufferUsed(&other.buffer_));
    }
    return *this;
  }
  TxStream& operator=(TxStream&& other)
  {
    if (this != &other) {
      DPS_TxBufferFree(&buffer_);
      ret_ = other.ret_;
      size_ = other.size_;
      buffer_.base = other.buffer_.base;
      buffer_.eob = other.buffer_.eob;
      buffer_.txPos = other.buffer_.txPos;
      other.ret_ = DPS_OK;
      other.size_ = 0;
      DPS_TxBufferClear(&other.buffer_);
    }
    return *this;
  }

  const uint8_t * data() const noexcept { return buffer_.base; }
  size_t size() const noexcept { return DPS_TxBufferUsed(&buffer_); }
  DPS_Status status() const { return ret_; }
  size_t size_needed() const { return size_; }

  inline TxStream & operator<<(const uint64_t n)
  {
    size_ += CBOR_SIZEOF_UINT(n);
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeUint(&buffer_, n);
    }
    return *this;
  }
  inline TxStream & operator<<(const uint32_t n) { return *this << (uint64_t)n; }
  inline TxStream & operator<<(const uint16_t n) { return *this << (uint64_t)n; }
  inline TxStream & operator<<(const uint8_t n) { return *this << (uint64_t)n; }

  inline TxStream & operator<<(const int64_t i)
  {
    size_ += CBOR_SIZEOF_INT(i);
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeInt(&buffer_, i);
    }
    return *this;
  }
  inline TxStream & operator<<(const int32_t n) { return *this << (int64_t)n; }
  inline TxStream & operator<<(const int16_t n) { return *this << (int64_t)n; }
  inline TxStream & operator<<(const int8_t n) { return *this << (int64_t)n; }
  inline TxStream & operator<<(const char n) { return *this << (int64_t)n; }

  inline TxStream & operator<<(const float f)
  {
    size_ += CBOR_SIZEOF_FLOAT();
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeFloat(&buffer_, f);
    }
    return *this;
  }
  inline TxStream & operator<<(const double d)
  {
    size_ += CBOR_SIZEOF_DOUBLE();
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeDouble(&buffer_, d);
    }
    return *this;
  }

  inline TxStream & operator<<(const std::string s)
  {
    size_ += CBOR_SIZEOF_STRING_AND_LENGTH(s.size());
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeStringAndLength(&buffer_, s.data(), s.size());
    }
    return *this;
  }

  template<typename T>
  inline TxStream & operator<<(const std::vector<T> v)
  {
    return encodeSequence(v.data(), v.size());
  }

  inline TxStream & operator<<(const std::vector<bool> v)
  {
    size_ += CBOR_SIZEOF_ARRAY(v.size());
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeArray(&buffer_, v.size());
    }
    for (size_t i = 0; i < v.size(); ++i) {
      *this << v[i];
    }
    return *this;
  }

  template<typename T>
  inline TxStream & serializeSequence(const T * items, size_t size)
  {
    return encodeSequence(items, size);
  }

  inline TxStream & serializeSequence(size_t size)
  {
    size_ += CBOR_SIZEOF_ARRAY(size);
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeArray(&buffer_, size);
    }
    return *this;
  }

  inline TxStream & operator<<(const bool b)
  {
    size_ += CBOR_SIZEOF_BOOLEAN();
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeBoolean(&buffer_, b);
    }
    return *this;
  }

  inline TxStream & operator<<(const TxStream & stream)
  {
    size_ += stream.size();
    if (ret_ == DPS_OK) {
      ret_ = CBOR_Copy(&buffer_, stream.data(), stream.size());
    }
    return *this;
  }

private:
  DPS_Status ret_;
  size_t size_;
  DPS_TxBuffer buffer_;

  template<typename T>
  inline TxStream & encodeSequence(const T * items, size_t size)
  {
    size_ += CBOR_SIZEOF_ARRAY(size);
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeArray(&buffer_, size);
    }
    for (size_t i = 0; i < size; ++i) {
      *this << items[i];
    }
    return *this;
  }

  inline TxStream & encodeSequence(const uint8_t * items, size_t size)
  {
    size_ += CBOR_SIZEOF_BYTES(size);
    if (ret_ == DPS_OK) {
      ret_ = CBOR_EncodeBytes(&buffer_, items, size);
    }
    return *this;
  }
};

class RxStream {
public:
  RxStream()
  {
    DPS_RxBufferClear(&buffer_);
  }
  ~RxStream()
  {
    DPS_RxBufferFree(&buffer_);
  }
  RxStream(const uint8_t * data, size_t size)
  {
    copy(data, data + size);
  }
  RxStream(const RxStream& other)
  {
    copy(other.buffer_.base, other.buffer_.eod);
  }
  RxStream(RxStream&& other)
  {
    buffer_.base = other.buffer_.base;
    buffer_.eod = other.buffer_.eod;
    buffer_.rxPos = other.buffer_.rxPos;
    DPS_RxBufferClear(&other.buffer_);
  }
  RxStream& operator=(const RxStream& other)
  {
    if (this != &other) {
      DPS_RxBufferFree(&buffer_);
      copy(other.buffer_.base, other.buffer_.eod);
    }
    return *this;
  }
  RxStream& operator=(RxStream&& other)
  {
    if (this != &other) {
      buffer_.base = other.buffer_.base;
      buffer_.eod = other.buffer_.eod;
      buffer_.rxPos = other.buffer_.rxPos;
      DPS_RxBufferClear(&other.buffer_);
    }
    return *this;
  }

  uint8_t * getBuffer() const
  {
    return buffer_.base;
  }
  size_t getBufferSize() const
  {
    return buffer_.eod - buffer_.base;
  }
  bool eof() const
  {
    return buffer_.rxPos >= buffer_.eod;
  }

  inline RxStream & operator>>(uint64_t & n)
  {
    DPS_Status ret = CBOR_DecodeUint(&buffer_, &n);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize uint64_t");
    }
    return *this;
  }
  inline RxStream & operator>>(uint32_t & n)
  {
    DPS_Status ret = CBOR_DecodeUint32(&buffer_, &n);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize uint32_t");
    }
    return *this;
  }
  inline RxStream & operator>>(uint16_t & n)
  {
    DPS_Status ret = CBOR_DecodeUint16(&buffer_, &n);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize uint16_t");
    }
    return *this;
  }
  inline RxStream & operator>>(uint8_t & n)
  {
    DPS_Status ret = CBOR_DecodeUint8(&buffer_, &n);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize uint8_t");
    }
    return *this;
  }

  inline RxStream & operator>>(int64_t & i)
  {
    DPS_Status ret = CBOR_DecodeInt(&buffer_, &i);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize int64_t");
    }
    return *this;
  }
  inline RxStream & operator>>(int32_t & i)
  {
    DPS_Status ret = CBOR_DecodeInt32(&buffer_, &i);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize int32_t");
    }
    return *this;
  }
  inline RxStream & operator>>(int16_t & i)
  {
    DPS_Status ret = CBOR_DecodeInt16(&buffer_, &i);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize int16_t");
    }
    return *this;
  }
  inline RxStream & operator>>(int8_t & i)
  {
    DPS_Status ret = CBOR_DecodeInt8(&buffer_, &i);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize int8_t");
    }
    return *this;
  }
  inline RxStream & operator>>(char & c)
  {
    int8_t i;
    DPS_Status ret = CBOR_DecodeInt8(&buffer_, &i);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize char");
    }
    c = i;
    return *this;
  }

  inline RxStream & operator>>(float & f)
  {
    DPS_Status ret = CBOR_DecodeFloat(&buffer_, &f);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize float");
    }
    return *this;
  }
  inline RxStream & operator>>(double & d)
  {
    DPS_Status ret = CBOR_DecodeDouble(&buffer_, &d);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize double");
    }
    return *this;
  }

  inline RxStream & operator>>(std::string & s)
  {
    char* data;
    size_t size;
    DPS_Status ret = CBOR_DecodeString(&buffer_, &data, &size);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize std::string");
    }
    if (!size) {
      s = std::string();
    } else {
      s = std::string(data, size);
    }
    return *this;
  }

  template<typename T>
  inline RxStream & operator>>(std::vector<T> & v)
  {
    size_t size;
    DPS_Status ret = CBOR_DecodeArray(&buffer_, &size);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize std::vector<>");
    }
    v.resize(size);
    for (size_t i = 0; i < size; ++i) {
      *this >> v[i];
    }
    return *this;
  }

  inline RxStream & operator>>(std::vector<bool> & v)
  {
    size_t size;
    DPS_Status ret = CBOR_DecodeArray(&buffer_, &size);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize std::vector<bool>");
    }
    v.resize(size);
    for (size_t i = 0; i < size; ++i) {
      int b;
      ret = CBOR_DecodeBoolean(&buffer_, &b);
      if (ret != DPS_OK) {
        throw std::runtime_error("failed to deserialize std::vector<bool>");
      }
      v[i] = b ? true : false;
    }
    return *this;
  }

  inline RxStream & operator>>(std::vector<uint8_t> & v)
  {
    uint8_t * items;
    size_t size;
    DPS_Status ret = CBOR_DecodeBytes(&buffer_, &items, &size);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize std::vector<uint8_t>");
    }
    v.assign(items, items + size);
    return *this;
  }

  template<typename T>
  inline RxStream & deserializeSequence(T * items, size_t size)
  {
    return decodeSequence(items, size);
  }

  inline RxStream & deserializeSequence(size_t * size)
  {
    DPS_Status ret = CBOR_DecodeArray(&buffer_, size);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize array");
    }
    return *this;
  }

  inline RxStream & deserializeSequenceSize(size_t * size)
  {
    uint8_t maj;
    DPS_Status ret = CBOR_Peek(&buffer_, &maj, size);
    if (ret != DPS_OK || (maj != CBOR_ARRAY && maj != CBOR_BYTES)) {
      throw std::runtime_error("failed to deserialize array size");
    }
    return *this;
  }

  inline RxStream & operator>>(bool & b)
  {
    int b_;
    DPS_Status ret = CBOR_DecodeBoolean(&buffer_, &b_);
    if (ret != DPS_OK) {
      throw std::runtime_error("failed to deserialize bool");
    }
    b = b_ ? true : false;
    return *this;
  }

private:
  DPS_RxBuffer buffer_;

  void
  copy(const uint8_t * begin, const uint8_t * end)
  {
    size_t size = end - begin;
    DPS_TxBuffer tmp;
    if (DPS_TxBufferInit(&tmp, NULL, size) != DPS_OK) {
      throw std::bad_alloc();
    }
    DPS_TxBufferAppend(&tmp, begin, size);
    DPS_TxBufferToRx(&tmp, &buffer_);
  }

  template<typename T>
  inline RxStream & decodeSequence(T * items, size_t size)
  {
    size_t size_;
    DPS_Status ret = CBOR_DecodeArray(&buffer_, &size_);
    if (ret != DPS_OK || size_ != size) {
      throw std::runtime_error("failed to deserialize array");
    }
    for (size_t i = 0; i < size; ++i) {
      *this >> items[i];
    }
    return *this;
  }

  inline RxStream & decodeSequence(uint8_t * items, size_t size)
  {
    uint8_t * items_;
    size_t size_;
    DPS_Status ret = CBOR_DecodeBytes(&buffer_, &items_, &size_);
    if (ret != DPS_OK || size_ != size) {
      throw std::runtime_error("failed to deserialize uint8_t array");
    }
    memcpy(items, items_, size);
    return *this;
  }
};

}

#endif
