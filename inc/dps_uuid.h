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

#endif
