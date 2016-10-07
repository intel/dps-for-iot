#include <uv.h>
#include "uv_extra.h"

#ifdef _WIN32
#else
#include <pthread.h>
#endif

int uv_thread_detach(uv_thread_t* tid)
{
    int r;
#ifdef _WIN32
    r = CloseHandle(*tid) ? 0 : UV_EINVAL;
#else
    r = -pthread_detach(*tid);
#endif
    *tid = 0;
    return r;
}
