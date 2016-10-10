#ifndef _DPS_DBG_H
#define _DPS_DBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int DPS_Debug;

typedef enum {
    DPS_LOG_ERROR,
    DPS_LOG_PRINT,
    DPS_LOG_DBGTRACE,
    DPS_LOG_DBGPRINT,
} DPS_LogLevel;

void DPS_Log(DPS_LogLevel level, const char* file, int line, const char *function, const char *fmt, ...);

#define DPS_ERRPRINT(fmt, ...) DPS_Log(DPS_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#define DPS_PRINT(fmt, ...) DPS_Log(DPS_LOG_PRINT, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#define DPS_DEBUG_OFF  0
#define DPS_DEBUG_ON   1

#define DPS_DEBUG_ENABLED()  (DPS_Debug && (__DPS_DebugControl == DPS_DEBUG_ON))

#ifdef DPS_DEBUG
#define DPS_DBGTRACE() (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_DBGTRACE, __FILE__, __LINE__, __FUNCTION__, "\n") : 0)
#define DPS_DBGPRINT(fmt, ...) (DPS_DEBUG_ENABLED() ? DPS_Log(DPS_LOG_DBGPRINT, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__) : 0)
#else
#define DPS_DBGTRACE() 
#define DPS_DBGPRINT(...) 
#endif

/*
 * Used at the top of a file to turn debugging on or off for that file
 */
#ifdef _WIN32
#define DPS_DEBUG_CONTROL(dbg) static int __DPS_DebugControl = dbg
#else
#define DPS_DEBUG_CONTROL(dbg) __attribute__((__unused__))static int __DPS_DebugControl = dbg
#endif

#ifdef __cplusplus
}
#endif

#endif
