#ifndef _DPS_UUID_H
#define _DPS_UUID_H

#include <stdint.h>
#include <dps_err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type definition for a UUID
 */
typedef struct {
    union {
        uint8_t val[16];
        uint64_t val64[4];
    };
} DPS_UUID;

/**
 * One time initialization
 */
DPS_Status DPS_InitUUID();

/**
 *  Non secure generation of a random UUID.
 */
void DPS_GenerateUUID(DPS_UUID* uuid);

/**
 * Return a string representation of a UUID. Not this function uses a static string and is non-reentrant.
 */
const char* DPS_UUIDToString(const DPS_UUID* uuid);

/**
 * Lexicographic comparison of two UUIDs
 */
int DPS_UUIDCompare(const DPS_UUID* a, const DPS_UUID* b);

#ifdef __cplusplus
}
#endif

#endif
