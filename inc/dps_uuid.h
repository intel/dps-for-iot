#ifndef _DPS_UUID_H
#define _DPS_UUID_H

#include <stdint.h>
#include <dps_err.h>

/**
 * Type definition for a UUID
 */
typedef struct {
    uint8_t val[16];
} DPS_UUID;

/**
 * Generate a UUID
 */
DPS_Status DPS_GenerateUUID(DPS_UUID* uuid);

/**
 * Return a string representation of a UUID. Not this function uses a static string and is non-reentrant.
 */
const char* DPS_UUIDToString(DPS_UUID* uuid);

#endif
