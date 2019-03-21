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

#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/synchronous.h>

int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return DPS_FALSE;
    }
    if (!--argc) {
        return DPS_FALSE;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return DPS_FALSE;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return DPS_FALSE;
    }
    *argp = arg;
    *argcp = argc;
    return DPS_TRUE;
}

int ListenArg(char*** argp, int* argcp, DPS_NodeAddress** addr)
{
    char** arg = *argp;
    int argc = *argcp;
    int port = 0;
    char str[256];

    strcpy(str, "[::]:0");

    if (IntArg("-l", &arg, &argc, &port, 1000, UINT16_MAX)) {
        snprintf(str, sizeof(str), "[::]:%d", port);
    } else if (strcmp(*arg, "-l") == 0) {
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

int LinkArg(char*** argp, int* argcp, char** addrText, int* numAddrText)
{
    char** arg = *argp;
    int argc = *argcp;
    int port = 0;
    char str[256];

    if (IntArg("-p", &arg, &argc, &port, 1000, UINT16_MAX)) {
        if ((*numAddrText) == (MAX_LINKS - 1)) {
            DPS_PRINT("Too many -p options\n");
            return DPS_FALSE;
        }
        snprintf(str, sizeof(str), "[::1]:%d", port);
        addrText[(*numAddrText)++] = strdup(str);
    } else if (strcmp(*arg, "-p") == 0) {
        if ((*numAddrText) == (MAX_LINKS - 1)) {
            DPS_PRINT("Too many -p options\n");
            return DPS_FALSE;
        }
        ++arg;
        if (!--argc) {
            return DPS_FALSE;
        }
        addrText[(*numAddrText)++] = strdup(*arg++);
    } else {
        return DPS_FALSE;
    }
    *argp = arg;
    *argcp = argc;
    return DPS_TRUE;
}

DPS_Status Link(DPS_Node* node, char** addrText, DPS_NodeAddress** addr, int numAddr)
{
    DPS_Status ret;
    int i;

    for (i = 0; i < numAddr; ++i) {
        addr[i] = DPS_CreateAddress();
        if (!addr[i]) {
            ret = DPS_ERR_RESOURCES;
            goto Exit;
        }
        ret = DPS_LinkTo(node, addrText[i], addr[i]);
        if (ret == DPS_OK) {
            DPS_PRINT("Node is linked to %s\n", DPS_NodeAddrToString(addr[i]));
        } else {
            DPS_ERRPRINT("DPS_LinkTo %s returned %s\n", addrText[i], DPS_ErrTxt(ret));
        }
    }
    ret = DPS_OK;

Exit:
    return ret;
}

void Unlink(DPS_Node* node, DPS_NodeAddress** addr, int numAddr)
{
    int i;
    for (i = 0; i < numAddr; ++i) {
        DPS_UnlinkFrom(node, addr[i]);
    }
}

void DestroyLinkArg(char **addrText, DPS_NodeAddress** addr, int numAddr)
{
    int i;
    for (i = 0; i < numAddr; ++i) {
        if (addrText[i]) {
            free(addrText[i]);
        }
        DPS_DestroyAddress(addr[i]);
    }
}
