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

#define _CRT_RAND_S

#include <stdint.h>
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/uuid.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if DPS_TARGET == DPS_TARGET_ZEPHYR
#include <rtc.h>
#include <entropy.h>
#endif

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

const char* DPS_UUIDToString(const DPS_UUID* uuid)
{
    static const char* hex = "0123456789abcdef";
    static char str[38];
    char* dst = str;
    const uint8_t *src = uuid->val;
    size_t i;

    for (i = 0; i < sizeof(uuid->val); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            *dst++ = '-';
        }
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xF];
    }
    *dst = 0;
    return str;
}

static struct {
    uint64_t nonce[2];
    uint32_t seeds[4];
} entropy;

#if DPS_TARGET == DPS_TARGET_WINDOWS
static void InitUUID(void)
{
    errno_t ret = 0;
    int i;
    uint32_t* n = (uint32_t*)&entropy;

    for (i = 0; i < (sizeof(entropy) / sizeof(uint32_t)); ++i) {
        rand_s(n++);
    }
}
#elif DPS_TARGET == DPS_TARGET_LINUX
/*
 * Linux specific implementation
 */
static const char* randPath = "/dev/urandom";

static void InitUUID()
{
    while (!entropy.nonce[0]) {
        FILE* f = fopen(randPath, "r");
        if (!f) {
            DPS_ERRPRINT("fopen(\"%s\", \"r\") failed\n", randPath);
            context.ret = DPS_ERR_READ;
            break;
        }
        fread(&entropy, 1, sizeof(entropy), f);
        fclose(f);
    }
}
#elif DPS_TARGET == DPS_TARGET_ZEPHYR

static void InitUUID()
{
    struct device* dev = device_get_binding(CONFIG_ENTROPY_NAME);
	if (!dev) {
		DPS_DBGPRINT("No entropy device\n");
    } else {
        int ret = entropy_get_entropy(dev, (void*)&entropy, sizeof(entropy));
        if (ret) {
            DPS_DBGPRINT("Failed to get entropy\n");
        }
    }
}

#else
#error "Unsupported target"
#endif


/*
 * Very simple linear congruational generator based PRNG (Lehmer/Park-Miller generator)
 */
#define LEPRNG(n)  (uint32_t)(((uint64_t)(n) * 279470273ull) % 4294967291ul)

/*
 * This is fast - not secure
 */
void DPS_GenerateUUID(DPS_UUID* uuid)
{
    static int once = 0;
    uint64_t* s = (uint64_t*)entropy.seeds;
    uint32_t s0;

    DPS_DBGTRACE();

    if (!once) {
        once = 1;
        InitUUID();
    }
    s0 = entropy.seeds[0];
    entropy.seeds[0] = LEPRNG(entropy.seeds[1]);
    entropy.seeds[1] = LEPRNG(entropy.seeds[2]);
    entropy.seeds[2] = LEPRNG(entropy.seeds[3]);
    entropy.seeds[3] = LEPRNG(s0);
    uuid->val64[0] = s[0] ^ entropy.nonce[0];
    uuid->val64[1] = s[1] ^ entropy.nonce[1];
}

int DPS_UUIDCompare(const DPS_UUID* a, const DPS_UUID* b)
{
    return memcmp(&a->val, &b->val, sizeof(a->val));
}

void DPS_RandUUIDLess(DPS_UUID* uuid)
{
    DPS_UUID tmp;
    int i;

    DPS_GenerateUUID(&tmp);
    /*
     * All this does is subtract a random 64 bit uint from an 128 bit uint
     */
    for (i = 15; i >= 8; --i) {
        if (tmp.val[i] > uuid->val[i]) {
            --uuid->val[i - 1];
        }
        uuid->val[i] -= tmp.val[i];
    }
}

uint32_t DPS_Rand()
{
    uint32_t s0;

    s0 = entropy.seeds[0];
    entropy.seeds[0] = LEPRNG(entropy.seeds[1]);
    entropy.seeds[1] = LEPRNG(entropy.seeds[2]);
    entropy.seeds[2] = LEPRNG(entropy.seeds[3]);
    entropy.seeds[3] = LEPRNG(s0);
    s0 = entropy.seeds[0];
    return s0;
}
