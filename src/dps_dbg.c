#include <dps/dps_dbg.h>
#include <stdarg.h>

int DPS_Debug = 1;

#define DPS_DBG_TIME   ((uint32_t)((uv_hrtime() / 1000000) & 0xFFFFFFF))

void DPS_Log(DPS_LogLevel level, const char* file, int line, const char *function, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    switch (level) {
    case DPS_LOG_ERROR:
        fprintf(stderr, "%09u:%s@%d\t ERROR! ", DPS_DBG_TIME, file, line);
        vfprintf(stderr, fmt, ap);
        break;
    case DPS_LOG_PRINT:
        vfprintf(stderr, fmt, ap);
        break;
    case DPS_LOG_DBGTRACE:
        fprintf(stderr, "%09u:%s@%d\t %s()\n", DPS_DBG_TIME, file, line, function);
        break;
    case DPS_LOG_DBGPRINT:
        fprintf(stderr, "%09u:%s@%d\t ", DPS_DBG_TIME, file, line);
        vfprintf(stderr, fmt, ap);
        break;
    }
    va_end(ap);
}
