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

/*
 * Unit test for internal history APIs
 *
 */
#include "test.h"
#include "history.h"

extern void DPS_DumpHistory(DPS_History* history);

static DPS_History history;

//#define READABLE_UUIDS
#define NUM_PUBS   1000

int main(int argc, char** argv)
{
    DPS_Status ret;
    int i = 0;
    uint32_t sn;
    DPS_UUID uuid[NUM_PUBS];
    DPS_NodeAddress addr;
    DPS_NodeAddress* addrPtr;

    DPS_Debug = DPS_FALSE;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d")) {
            DPS_Debug = DPS_TRUE;
        }
    }

    memset(&addr, 0, sizeof(addr));
#if defined(DPS_USE_DTLS)
    addr.type = DPS_DTLS;
    addr.u.inaddr.ss_family = AF_INET6;
#elif defined(DPS_USE_TCP)
    addr.type = DPS_TCP;
    addr.u.inaddr.ss_family = AF_INET6;
#elif defined(DPS_USE_UDP)
    addr.type = DPS_UDP;
    addr.u.inaddr.ss_family = AF_INET6;
#elif defined(DPS_USE_PIPE)
    addr.type = DPS_PIPE;
#endif

    ret = DPS_InitUUID();
    if (ret != DPS_OK) {
        DPS_PRINT("DPS_InitUUID failed\n");
        return EXIT_FAILURE;
    }

    history.loop = uv_default_loop();
    uv_mutex_init(&history.lock);

#ifdef READABLE_UUIDS
    /*
     * This makes debugging easier
     */
    memset(uuid, 0, sizeof(uuid));
    i = 0;
    while (i < NUM_PUBS) {
        int n = rand() % NUM_PUBS;
        if (uuid[n].val64[0] == 0) {
            uuid[n].val64[0] = ++i;
        }
    }
#else
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_GenerateUUID(&uuid[i]);
    }
#endif
    /*
     * Add entries
     */
    DPS_PRINT("Add entries\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, DPS_TRUE, 0, &addr);
    }
    /*
     * Check there are all there
     */
    DPS_PRINT("Check all entries present\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisherForAck(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return EXIT_FAILURE;
        }
    }
    /*
     * Remove some
     */
    DPS_PRINT("Remove some entries\n");
    for (i = 0; i < NUM_PUBS / 4; ++i) {
        if (DPS_DeletePubHistory(&history, &uuid[i]) != DPS_OK) {
            DPS_PRINT("Pub history delete failed\n");
            return EXIT_FAILURE;
        }
    }
    /*
     * Check remaining pubs are still there
     */
    DPS_PRINT("Check remaining entries\n");
    for (i = NUM_PUBS / 4; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisherForAck(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return EXIT_FAILURE;
        }
    }
    /*
     * Put them back
     */
    DPS_PRINT("Replace removed entries\n");
    for (i = 0; i < NUM_PUBS / 4; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, DPS_TRUE, 0, &addr);
    }
    /*
     * Check there are all there
     */
    DPS_PRINT("Check all entries present after replacement\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisherForAck(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return EXIT_FAILURE;
        }
    }
    /*
     * Protect some by setting a longer timeout
     */
    for (i = NUM_PUBS / 4; i < NUM_PUBS / 3; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, DPS_TRUE, 20, &addr);
    }
    /*
     * Wait a while - default timeout is 10 seconds
     */
    DPS_PRINT("Wait for history to expire\n");
    SLEEP(12 * 1000);
    /*
     * Expire the stale entries
     */
    DPS_FreshenHistory(&history);
    /*
     * Check protected entries are still there and others have expired
     */
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_Status ret = DPS_LookupPublisherForAck(&history, &uuid[i], &sn, &addrPtr);
        if (i >= NUM_PUBS / 4 &&  i < NUM_PUBS / 3) {
            if (ret != DPS_OK) {
                DPS_PRINT("Pub history is missing\n");
                return EXIT_FAILURE;
            }
        } else {
            if (ret != DPS_ERR_MISSING) {
                DPS_PRINT("Pub history was not expired\n");
                return EXIT_FAILURE;
            }
        }
    }
    DPS_HistoryFree(&history);

    DPS_PRINT("Unit test passed\n");

    return EXIT_SUCCESS;

}
