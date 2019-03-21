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

#ifndef _COMMON_H
#define _COMMON_H

#include <dps/dps.h>

#if defined(_MSC_VER)
#define strdup _strdup
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LINKS 16

int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max);
int ListenArg(char*** argp, int* argcp, DPS_NodeAddress** addr);
int LinkArg(char*** argp, int* argcp, char** addrText, int* numAddrText);
DPS_Status Link(DPS_Node* node, char** addrText, DPS_NodeAddress** addr, int numAddr);
void Unlink(DPS_Node* node, DPS_NodeAddress** addr, int numAddr);
void DestroyLinkArg(char **addrText, DPS_NodeAddress** addr, int numAddr);

#ifdef __cplusplus
}
#endif

#endif
