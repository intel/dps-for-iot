/**
 * @file
 * Create and compare UUIDs
 */

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

#ifndef _DPS_UUID_H
#define _DPS_UUID_H

#include <stdint.h>
#include <dps/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup uuid UUID
 * Create and compare UUIDs.
 * @{
 */

/**
 * Type definition for a UUID
 */
typedef struct _DPS_UUID {
    /**< The UUID value */
    union {
        uint8_t val[16]; /**< The UUID as an array of 8-bit values */
        uint64_t val64[2]; /**< The UUID as an array of 64-bit values */
    };
} DPS_UUID;

/**
 * One time initialization
 *
 * @return DPS_OK if initialization succeeds, an error otherwise
 */
DPS_Status DPS_InitUUID();

/**
 * Non secure generation of a random UUID.
 *
 * @param uuid The generated UUID.
 */
void DPS_GenerateUUID(DPS_UUID* uuid);

/**
 * Return a string representation of a UUID.
 *
 * @note This function uses a static string and is non-reentrant.
 *
 * @param uuid The UUID
 *
 * @return The string representation
 */
const char* DPS_UUIDToString(const DPS_UUID* uuid);

/**
 * Numerical comparison of two UUIDs
 *
 * @param a One of the UUIDs to compare
 * @param b The other UUID to compare
 *
 * @return
 * - <0 if a less than b
 * - 0 if a equal to b
 * - >0 if a greater than b
 */
int DPS_UUIDCompare(const DPS_UUID* a, const DPS_UUID* b);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
