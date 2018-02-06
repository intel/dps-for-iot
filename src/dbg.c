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

#include <dps/dbg.h>
#include <safe_lib.h>
#include <uv.h>
#include <stdarg.h>

int DPS_Debug = 1;

#define DPS_DBG_TIME   ((uint32_t)((uv_hrtime() / 1000000) & 0xFFFFFFF))

static const char* LevelTxt[] = { "ERROR", "WARNING", "" /* PRINT */, "" /* PRINTT */, "TRACE", "DEBUG" };

void DPS_Log(DPS_LogLevel level, const char* file, int line, const char *function, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    switch (level) {
    case DPS_LOG_ERROR:
    case DPS_LOG_WARNING:
    case DPS_LOG_DBGPRINT:
        fprintf(stderr, "%09u %-7s %s@%d: ", DPS_DBG_TIME, LevelTxt[level], file, line);
        vfprintf(stderr, fmt, ap);
        break;
    case DPS_LOG_PRINTT:
        fprintf(stderr, "%09u ", DPS_DBG_TIME);
        /* FALLTHROUGH */
    case DPS_LOG_PRINT:
        vfprintf(stderr, fmt, ap);
        break;
    case DPS_LOG_DBGTRACE:
        fprintf(stderr, "%09u %-7s %s@%d: %s() ", DPS_DBG_TIME, LevelTxt[level], file, line, function);
        vfprintf(stderr, fmt, ap);
        break;
    }
    va_end(ap);
}

void DPS_LogBytes(DPS_LogLevel level, const char* file, int line, const char *function, const uint8_t *bytes, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if ((i % 16) == 0) {
            fprintf(stderr, "%s%09u %-7s %s@%d: ", i ? "\n" : "", DPS_DBG_TIME, LevelTxt[level], file, line);
        }
        fprintf(stderr, "%02x ", bytes[i]);
    }
    fprintf(stderr, "\n");
}
