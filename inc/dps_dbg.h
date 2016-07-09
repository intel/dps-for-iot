#ifndef _DPS_DBG_H
#define _DPS_DBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <uv.h>

extern int DPS_Debug;

#define DPS_DBG_TIME   ((uint32_t)((uv_hrtime() / 1000000) & 0xFFFFFFF))

#define DPS_ERRPRINT(fmt, ...) fprintf(stderr, "%09u:%s@%d\t ERROR! " fmt, DPS_DBG_TIME, __FILE__, __LINE__, __VA_ARGS__ + 0)

#define DPS_PRINT(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__ + 0)

#define DPS_DEBUG_OFF  0
#define DPS_DEBUG_ON   1

#define DPS_DEBUG_ENABLED()  (DPS_Debug && (__DPS_DebugControl == DPS_DEBUG_ON))

#ifdef DPS_DEBUG
#define DPS_DBGTRACE() (DPS_DEBUG_ENABLED() ? fprintf(stderr, "%09u:%s@%d\t %s()\n", DPS_DBG_TIME, __FILE__, __LINE__, __FUNCTION__) : 0)
#define DPS_DBGPRINT(fmt, ...) (DPS_DEBUG_ENABLED() ? fprintf(stderr, "%09u:%s@%d\t " fmt, DPS_DBG_TIME, __FILE__, __LINE__, __VA_ARGS__ + 0) : 0)
#else
#define DPS_DBGTRACE() 
#define DPS_DBGPRINT(...) 
#endif

/*
 * Used at the top of a file to turn debugging on or off for that file
 */
#define DPS_DEBUG_CONTROL(dbg) static int __DPS_DebugControl = dbg

#endif
