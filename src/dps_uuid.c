#ifdef _WIN32
#define _CRT_RAND_S
#include <stdlib.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <dps_dbg.h>
#include <dps_uuid.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static inline uint8_t BIN(char c)
{
    return c <= '9' ? c - '0' : 10 + c - 'a';
}

const char* DPS_UUIDToString(const DPS_UUID* uuid)
{
    static const char* hex = "0123456789abcdef";
    static char str[38];
    char* p = str;
    size_t i;

    for (i = 0; i < sizeof(uuid->val); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            *p++ = '-';
        }
        *p++ = hex[uuid->val[i] >> 4];
        *p++ = hex[uuid->val[i] & 0xF];
    }
    *p = 0;
    return str;
}

static struct {
    uint64_t nonce[2];
    uint32_t seeds[4];
} entropy; 

#ifdef _WIN32
DPS_Status DPS_InitUUID()
{
    errno_t ret = 0;
    int i;
    uint32_t* n = (uint32_t*)&entropy;

    for (i = 0; i < (sizeof(entropy) / sizeof(uint32_t)); ++i) {
        ret = rand_s(n++);
        if (ret) {
            return DPS_ERR_FAILURE;
        }
    }
    return DPS_OK;
}
#else
/*
 * Linux specific implementation
 */
static const char* randPath = "/dev/urandom";

DPS_Status DPS_InitUUID()
{
    while (!entropy.nonce[0]) {
        size_t sz;
        FILE* f = fopen(randPath, "r");
        if (!f) {
            DPS_ERRPRINT("fopen(\"%s\", \"r\") failed\n", randPath);
            return DPS_ERR_READ;
        }
        sz = fread(&entropy, 1, sizeof(entropy), f);
        fclose(f);
        if (sz != sizeof(entropy)) {
            return DPS_ERR_READ;
        }
    }
    return DPS_OK;
}
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
    uint64_t* s = (uint64_t*)entropy.seeds;
    uint32_t s0 = entropy.seeds[0];
    entropy.seeds[0] = LEPRNG(entropy.seeds[1]);
    entropy.seeds[1] = LEPRNG(entropy.seeds[2]);
    entropy.seeds[2] = LEPRNG(entropy.seeds[3]);
    entropy.seeds[3] = LEPRNG(s0);
    uuid->val64[0] = s[0] ^ entropy.nonce[0];
    uuid->val64[1] = s[1] ^ entropy.nonce[1];
}

int DPS_UUIDCompare(const DPS_UUID* a, const DPS_UUID* b)
{
    if (a->val64[0] < b->val64[0]) {
        return -1;
    }
    if (a->val64[0] > b->val64[0]) {
        return 1;
    }
    if (a->val64[1] < b->val64[1]) {
        return -1;
    }
    if (a->val64[1] > b->val64[1]) {
        return 1;
    }
    return 0;
}
