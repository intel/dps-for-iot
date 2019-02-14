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

#ifndef _COMPAT_H
#define _COMPAT_H


#include <string.h>
#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif

#define DPS_TARGET_WINDOWS   1
#define DPS_TARGET_LINUX     2
#define DPS_TARGET_ZEPHYR    3

/*
 * Code required for platform compatibility
 */

#if DPS_TARGET == DPS_TARGET_WINDOWS

#define DPS_TARGET_NAME "Windows"

#include <windows.h>

static inline char* strndup(const char* str, size_t maxLen)
{
    size_t len = strnlen(str, maxLen + 1);
    if (len > maxLen) {
        len = maxLen;
    }
    char* c = malloc(len + 1);
    if (c) {
        memcpy(c, str, len);
        c[len] = '\0';
    }
    return c;
}

#define BSWAP_32(n)  _byteswap_ulong(n)
#define BSWAP_64(n)  _byteswap_uint64(n)

#define __LITTLE_ENDIAN   0
#define __BIG_ENDIAN      1
#define __BYTE_ORDER      __LITTLE_ENDIAN

#elif DPS_TARGET == DPS_TARGET_LINUX

#define DPS_TARGET_NAME "Linux"

#include <endian.h>

#define BSWAP_32(n)  __builtin_bswap32(n)
#define BSWAP_64(n)  __builtin_bswap64(n)

#elif DPS_TARGET == DPS_TARGET_ZEPHYR

#define DPS_TARGET_NAME "Zephyr"

#include <zephyr.h>
#include <misc/byteorder.h>

#define __LITTLE_ENDIAN   __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN      __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER      __BYTE_ORDER__

#define BSWAP_32(n)  __bswap_32(n)
#define BSWAP_64(n)  __bswap_64(n)

static inline size_t strnlen(const char* str, size_t maxLen)
{
    size_t len = maxLen;
    while (len && *str++) {
        --len;
    }
    return maxLen - len;
}

static inline char* strndup(const char* str, size_t maxLen)
{
    size_t len = strnlen(str, maxLen + 1);
    if (len > maxLen) {
        len = maxLen;
    }
    char* c = malloc(len + 1);
    if (c) {
        memcpy(c, str, len);
        c[len] = '\0';
    }
    return c;
}

static inline size_t strcspn(const char* str1, const char* str2)
{
    const char* s1 = str1;
    while (*s1) {
        const char* s2 = str2;
        while (*s2) {
            if (*s1 == *s2) {
                goto Exit;
            }
            ++s2;
        }
        ++s1;
    }
Exit:
    return s1 - str1;
}
#else

#error "Unsupported target"

#endif

#ifdef __cplusplus
}
#endif

#endif
