/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
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
#include "dps/private/network.h"

static const char addr1[] = "[::ffff:192.168.181.130]:49911";
static const char addr2[] = "192.168.181.130:49911";


int main(int argc, char** argv)
{
    DPS_NodeAddress a1;
    DPS_NodeAddress a2;
    const char* check;
    int i;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    DPS_SetAddress(&a1, addr1);
    check = DPS_NetAddrText((struct sockaddr*)&a1.u.inaddr);
    if (strcmp(check, addr1) != 0) {
        DPS_PRINT("Failed %s != %s\n", check, addr1);
    }

    DPS_SetAddress(&a2, addr2);
    check = DPS_NetAddrText((struct sockaddr*)&a2.u.inaddr);
    if (strcmp(check, addr2) != 0) {
        DPS_PRINT("Failed %s != %s\n", check, addr2);
    }

    if (!DPS_SameAddr(&a1, &a2)) {
        char str1[64];
        char str2[64];
        strcpy(str1, DPS_NetAddrText((struct sockaddr*)&a1.u.inaddr));
        strcpy(str2, DPS_NetAddrText((struct sockaddr*)&a2.u.inaddr));
        DPS_PRINT("Failed %s != %s\n", str1, str2);
    }
    return EXIT_SUCCESS;
}
