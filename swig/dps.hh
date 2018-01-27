/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#ifndef _DPS_HH
#define _DPS_HH

#include <vector>
#include <string>
#include <dps/dps.h>

namespace dps {

class Key : public DPS_Key {
public:
    virtual ~Key() { }
};

class SymmetricKey : public Key {
public:
    SymmetricKey(const uint8_t* key, size_t len);
private:
    std::vector<uint8_t> m_key;
};

class ECKey : public Key {
public:
    ECKey(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y, const uint8_t* d);
    size_t CoordinateSize() const;
private:
    std::vector<uint8_t> m_x;
    std::vector<uint8_t> m_y;
    std::vector<uint8_t> m_d;
};

class CertKey : public Key {
public:
    CertKey(const char *_cert, const char *privateKey, const char *password);
    CertKey(const char *_cert);
private:
    std::string m_cert;
    std::string m_privateKey;
    std::string m_password;
};

};

#endif
