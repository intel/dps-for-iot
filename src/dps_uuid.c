#include <stdint.h>
#include <stdio.h>
#include <dps_dbg.h>
#include <dps_uuid.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

/*
 * Linux specific implementation
 */
static const char* uuidPath = "/proc/sys/kernel/random/uuid";

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

DPS_Status DPS_GenerateUUID(DPS_UUID* uuid)
{
    size_t sz;
    char uuidStr[40];
    char* p = uuidStr;
    FILE* f = fopen(uuidPath, "r");
    if (!f) {
        DPS_ERRPRINT("fopen(\"%s\", \"r\") failed\n", uuidPath);
        return DPS_ERR_READ;
    }
    sz = fread(uuidStr, 1, sizeof(uuidStr), f);
    fclose(f);
    uuidStr[sz] = 0;
    for (sz = 0; sz < sizeof(uuid->val); ++sz) {
        if (!*p) {
            return DPS_ERR_INVALID;
        }
        uuid->val[sz] = BIN(*p++) << 4 | BIN(*p++);
        if (*p == '-') {
            ++p;
        }
    }
    return DPS_OK;
}

