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

#include <stdarg.h>
#include <dps/dbg.h>

int DPS_Debug = 1;

/* TODO - platform dependent timestamp */
#define DPS_DBG_TIME   0

static const char* LevelTxt[] = { "ERROR", "WARNING", "" /* PRINT */, "" /* PRINTT */, "TRACE", "DEBUG" };

#define stream stdout

void DPS_Log(DPS_LogLevel level, const char* file, int line, const char *function, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    switch (level) {
    case DPS_LOG_ERROR:
    case DPS_LOG_WARNING:
    case DPS_LOG_DBGPRINT:
        fprintf(stream, "%09u %-7s %s@%d: ", DPS_DBG_TIME, LevelTxt[level], file, line);
        vfprintf(stream, fmt, ap);
        break;
    case DPS_LOG_PRINTT:
        fprintf(stream, "%09u ", DPS_DBG_TIME);
        /* FALLTHROUGH */
    case DPS_LOG_PRINT:
        vfprintf(stream, fmt, ap);
        break;
    case DPS_LOG_DBGTRACE:
        fprintf(stream, "%09u %-7s %s@%d: %s() ", DPS_DBG_TIME, LevelTxt[level], file, line, function);
        vfprintf(stream, fmt, ap);
        break;
    }
    va_end(ap);
}

void DPS_LogBytes(DPS_LogLevel level, const char* file, int line, const char *function, const uint8_t *bytes, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        if ((i % 16) == 0) {
            fprintf(stream, "%s%09u %-7s %s@%d: ", i ? "\n" : "", DPS_DBG_TIME, LevelTxt[level], file, line);
        }
        fprintf(stream, "%02x ", bytes[i]);
    }
    fprintf(stream, "\n");
}
