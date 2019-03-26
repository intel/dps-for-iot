/*
 *******************************************************************
 *
 * Copyright 2016 Intel Corporation All rights reserved.
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

#include <stdio.h>
#include <dps/err.h>

#define ERR_CASE(_s) case _s: return # _s + 8

const char* DPS_ErrTxt(DPS_Status s)
{
    static char buf[8];

    switch (s) {
        ERR_CASE(DPS_ERR_OK);
        ERR_CASE(DPS_ERR_FAILURE);
        ERR_CASE(DPS_ERR_NULL);
        ERR_CASE(DPS_ERR_ARGS);
        ERR_CASE(DPS_ERR_RESOURCES);
        ERR_CASE(DPS_ERR_READ);
        ERR_CASE(DPS_ERR_WRITE);
        ERR_CASE(DPS_ERR_TIMEOUT);
        ERR_CASE(DPS_ERR_EOD);
        ERR_CASE(DPS_ERR_OVERFLOW);
        ERR_CASE(DPS_ERR_NETWORK);
        ERR_CASE(DPS_ERR_INVALID);
        ERR_CASE(DPS_ERR_BUSY);
        ERR_CASE(DPS_ERR_EXISTS);
        ERR_CASE(DPS_ERR_MISSING);
        ERR_CASE(DPS_ERR_STALE);
        ERR_CASE(DPS_ERR_NO_ROUTE);
        ERR_CASE(DPS_ERR_NOT_STARTED);
        ERR_CASE(DPS_ERR_NOT_INITIALIZED);
        ERR_CASE(DPS_ERR_EXPIRED);
        ERR_CASE(DPS_ERR_UNRESOLVED);
        ERR_CASE(DPS_ERR_NODE_DESTROYED);
        ERR_CASE(DPS_ERR_EOF);
        ERR_CASE(DPS_ERR_NOT_IMPLEMENTED);
        ERR_CASE(DPS_ERR_SECURITY);
        ERR_CASE(DPS_ERR_NOT_ENCRYPTED);
        ERR_CASE(DPS_ERR_STOPPING);
        ERR_CASE(DPS_ERR_RANGE);
        ERR_CASE(DPS_ERR_LOST_PRECISION);
        ERR_CASE(DPS_ERR_NO_DATA);
    default:
        snprintf(buf, sizeof(buf), "ERR%d", s);
        return buf;
    }
}
