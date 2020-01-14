/**
 * @file
 * Debug and logging macros and functions
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

#ifndef _DPS_DBG_H
#define _DPS_DBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup debug Debug
 * Debug and logging macros and functions.
 * @{
 */

/** Debug control value */
extern int DPS_Debug;

/**
 * Debug logging levels
 */
typedef enum {
    DPS_LOG_ERROR,
    DPS_LOG_WARNING,
    DPS_LOG_PRINT,
    DPS_LOG_PRINTT,
    DPS_LOG_DBGTRACE,
    DPS_LOG_DBGPRINT,
} DPS_LogLevel;

/**
 * Log a message
 *
 * @param level the logging level
 * @param file the file name of the message
 * @param line the file line of the message
 * @param function the function name of the message
 * @param fmt the printf style format of the message
 * @param ... the format parameters
 */
void DPS_Log(DPS_LogLevel level, const char* file, int line, const char *function, const char *fmt, ...);

/**
 * Log an array of bytes
 *
 * @param level the logging level
 * @param file the file name of the message
 * @param line the file line of the message
 * @param function the function name of the message
 * @param bytes the array of bytes
 * @param n the number of bytes in the array
 */
void DPS_LogBytes(DPS_LogLevel level, const char* file, int line, const char *function, const uint8_t *bytes, size_t n);

/**
 * Log a message at ERROR level
 */
#define DPS_ERRPRINT(fmt, ...) DPS_Log(DPS_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

/**
 * Log a message at PRINT level
 */
#define DPS_PRINT(fmt, ...) DPS_Log(DPS_LOG_PRINT, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

/**
 * Same as DPS_PRINT but prepends a system timestamp
 */
#define DPS_PRINTT(fmt, ...) DPS_Log(DPS_LOG_PRINTT, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#define DPS_DEBUG_OFF   0 /**< Disable debug logging */
#define DPS_DEBUG_ON    1 /**< Enable debug logging */
#define DPS_DEBUG_FORCE 2 /**< Force debug logging */

/**
 * True if DPS debug logging is enabled
 */
#define DPS_DEBUG_ENABLED()  ((DPS_Debug && (__DPS_DebugControl == DPS_DEBUG_ON)) || (__DPS_DebugControl == DPS_DEBUG_FORCE))

#ifdef DPS_DEBUG
/**
 * Log a function name at DBGTRACE level
 */
#define DPS_DBGTRACE() (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_DBGTRACE, __FILE__, __LINE__, __FUNCTION__, "\n") : (void)0)
/**
 * Log a function name and message at DBGTRACE level
 */
#define DPS_DBGTRACEA(fmt, ...) (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_DBGTRACE, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__) : (void)0)
/**
 * Log a message at DBGPRINT level
 */
#define DPS_DBGPRINT(fmt, ...) (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_DBGPRINT, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__) : (void)0)
/**
 * Log a message at WARNING level
 */
#define DPS_WARNPRINT(fmt, ...) (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_WARNING, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__) : (void)0)
/**
 * Log an array of bytes at DBGPRINT level
 */
#define DPS_DBGBYTES(bytes, n) (DPS_DEBUG_ENABLED() ? DPS_LogBytes(DPS_LOG_DBGPRINT, __FILE__, __LINE__, __FUNCTION__, bytes, n) : (void)0)
#else
#define DPS_DBGTRACE()
#define DPS_DBGTRACEA(...)
#define DPS_DBGPRINT(...)
#define DPS_WARNPRINT(...)
#define DPS_DBGBYTES(bytes, n)
#endif

/**
 * Used at the top of a file to turn debugging on or off for that file
 */
#ifdef _WIN32
#define DPS_DEBUG_CONTROL(dbg) static int __DPS_DebugControl = dbg
#else
#define DPS_DEBUG_CONTROL(dbg) __attribute__((__unused__))static int __DPS_DebugControl = dbg
#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif
