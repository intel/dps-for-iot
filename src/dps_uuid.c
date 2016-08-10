#include <stdint.h>
#include <stdio.h>
#include <dps_dbg.h>
#include <sha1.h>
#include <dps_uuid.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Linux specific implementation
 */
static const char* randPath = "/dev/urandom";

static inline uint8_t BIN(char c)
{
    return c <= '9' ? c - '0' : 10 + c - 'a';
}

const char* DPS_UUIDToString(DPS_UUID* uuid)
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

/*
 * Very simple linear congruational generator based PRNG (Lehmer/Park-Miller generator) 
 */
#define LEPRNG(n)  (uint32_t)(((uint64_t)(n) * 279470273ull) % 4294967291ul)

/*
 * This is fast - not secure
 */
void DPS_GenerateUUID(DPS_UUID* uuid)
{
    uint64_t* u = (uint64_t*)uuid;
    uint64_t* s = (uint64_t*)entropy.seeds;
    uint32_t s0 = entropy.seeds[0];
    entropy.seeds[0] = LEPRNG(entropy.seeds[1]);
    entropy.seeds[1] = LEPRNG(entropy.seeds[2]);
    entropy.seeds[2] = LEPRNG(entropy.seeds[3]);
    entropy.seeds[3] = LEPRNG(s0);
    u[0] = s[0] ^ entropy.nonce[0];
    u[1] = s[1] ^ entropy.nonce[1];
}

