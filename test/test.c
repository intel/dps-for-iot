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

#include "test.h"

int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return 0;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

int AddressArg(char* opt, char*** argp, int* argcp, DPS_NodeAddress** addr)
{
    char** arg = *argp;
    int argc = *argcp;
    int port = 0;
    char str[256];

    strcpy(str, "[::]:0");

    if (IntArg(opt, &arg, &argc, &port, 1000, UINT16_MAX)) {
        snprintf(str, sizeof(str), "[::]:%d", port);
    } else if (strcmp(*arg, opt) == 0) {
        ++arg;
        if (!--argc) {
            return DPS_FALSE;
        }
        strncpy(str, *arg++, sizeof(str));
    } else {
        return DPS_FALSE;
    }
    *addr = DPS_CreateAddress();
    if (!*addr) {
        return DPS_FALSE;
    }
    if (!DPS_SetAddress(*addr, str)) {
        DPS_DestroyAddress(*addr);
        *addr = NULL;
        return DPS_FALSE;
    }
    *argp = arg;
    *argcp = argc;
    return DPS_TRUE;
}
