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

#include "dps.hh"

namespace dps {

SymmetricKey::SymmetricKey(const uint8_t* key, size_t len)
    : m_key(key, key + len)
{
    type = DPS_KEY_SYMMETRIC;
    symmetric.key = m_key.data();
    symmetric.len = m_key.size();
}

ECKey::ECKey(DPS_ECCurve curve, const uint8_t* x, const uint8_t* y, const uint8_t* d)
{
    type = DPS_KEY_EC;
    ec.curve = curve;
    size_t len = CoordinateSize();
    if (x) {
        m_x.assign(x, x + len);
        ec.x = m_x.data();
    } else {
        ec.x = NULL;
    }
    if (y) {
        m_y.assign(y, y + len);
        ec.y = m_y.data();
    } else {
        ec.y = NULL;
    }
    if (d) {
        m_d.assign(d, d + len);
        ec.d = m_d.data();
    } else {
        ec.d = NULL;
    }
}

size_t ECKey::CoordinateSize() const
{
    switch (ec.curve) {
    case DPS_EC_CURVE_P256: return 32;
    case DPS_EC_CURVE_P384: return 48;
    case DPS_EC_CURVE_P521: return 66;
    default:                return 0;
    }
}

CertKey::CertKey(const char *_cert, const char *privateKey, const char *password)
    : m_cert(_cert ? _cert : ""), m_privateKey(privateKey ? privateKey : ""),
      m_password(password ? password : "")
{
    type = DPS_KEY_EC_CERT;
    cert.cert = _cert ? m_cert.c_str() : NULL;
    cert.privateKey = privateKey ? m_privateKey.c_str() : NULL;
    cert.password = password ? m_password.c_str() : NULL;
}

CertKey::CertKey(const char *_cert)
    : m_cert(_cert ? _cert : "")
{
    type = DPS_KEY_EC_CERT;
    cert.cert = _cert ? m_cert.c_str() : NULL;
    cert.privateKey = NULL;
    cert.password = NULL;
}

};
