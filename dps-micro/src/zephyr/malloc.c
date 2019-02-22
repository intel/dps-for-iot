/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
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

#include <string.h>
#include <kernel.h>
#include <dps/private/malloc.h>

K_MEM_POOL_DEFINE(briefPool, 64, 2048, 2, 4);
K_MEM_POOL_DEFINE(longtermPool, 64, 1024, 6, 4);
K_MEM_POOL_DEFINE(permanentPool, 64, 4096, 4, 4);

void* DPS_Malloc(size_t len, DPS_AllocPool pool)
{
    switch (pool) {
    case DPS_ALLOC_BRIEF:
        return k_mem_pool_malloc(&briefPool, len);
    case DPS_ALLOC_LONG_TERM:
        return k_mem_pool_malloc(&longtermPool, len);
    case DPS_ALLOC_PERMANENT:
        return k_mem_pool_malloc(&permanentPool, len);
    }
    return NULL;
}

void* DPS_Calloc(size_t len, DPS_AllocPool pool)
{
    void* mem = DPS_Malloc(len, pool);
    if (mem) {
        memset(mem, 0, len);
    }
    return mem;
}

void DPS_Free(void* mem, DPS_AllocPool pool)
{
    k_free(mem);
}

void* DPS_CallocCrypto(size_t num, size_t len)
{
    return DPS_Calloc(num * len, DPS_ALLOC_LONG_TERM);
}

void DPS_FreeCrypto(void* mem)
{
    DPS_Free(mem, DPS_ALLOC_LONG_TERM);
}
