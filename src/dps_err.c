#include <stdio.h>
#include <dps_err.h>

#define ERR_CASE(_s) case _s: return # _s + 8

const char* DPS_ErrTxt(DPS_Status s)
{
    static char buf[8];

    switch (s) {
        ERR_CASE(DPS_ERR_OK);
        ERR_CASE(DPS_ERR_FAILURE);
        ERR_CASE(DPS_ERR_NULL);
        ERR_CASE(DPS_ERR_ARGS);
        ERR_CASE(DPS_ERR_RESOURCES);
        ERR_CASE(DPS_ERR_READ);
        ERR_CASE(DPS_ERR_WRITE);
        ERR_CASE(DPS_ERR_TIMEOUT);
        ERR_CASE(DPS_ERR_EOD);
        ERR_CASE(DPS_ERR_OVERFLOW);
        ERR_CASE(DPS_ERR_NETWORK);
        ERR_CASE(DPS_ERR_INVALID);
        ERR_CASE(DPS_ERR_BUSY);
        ERR_CASE(DPS_ERR_EXISTS);
        ERR_CASE(DPS_ERR_MISSING);
        ERR_CASE(DPS_ERR_STALE);
        ERR_CASE(DPS_ERR_NO_ROUTE);
        ERR_CASE(DPS_ERR_NOT_STARTED);
        ERR_CASE(DPS_ERR_NOT_INITIALIZED);
    default:
        snprintf(buf, sizeof(buf), "ERR%d", s);
        return buf;
    }
}
