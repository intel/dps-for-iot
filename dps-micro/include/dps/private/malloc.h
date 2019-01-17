/**
 * @file
 * Abstraction layer for memory allocation
 */

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

#ifndef _DPS_MALLOC_H
#define _DPS_MALLOC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * To avoid fragmentation on embedded targets will limited resources memory allocations
 * are segmented into pools based on the lifetime of the allocation.
 */

typedef enum {
    DPS_ALLOC_BRIEF,      /**< Pool for allocations that are short term - e.g. within one function */
    DPS_ALLOC_LONG_TERM,  /**< Pool for allocations that are longer term - e.g. until a callback is made */
    DPS_ALLOC_PERMANENT,  /**< Pool for allocations that are for the lifetime of the application */
} DPS_AllocPool;

/**
  * Allocate memory from one of the pools
  */
void* DPS_Malloc(size_t len, DPS_AllocPool pool);

/**
  * Allocate and clear memory from one of the pools
  */
void* DPS_Calloc(size_t len, DPS_AllocPool pool);

/**
  * Return memory to the pool from which it was allocated
  */
void DPS_Free(void* mem, DPS_AllocPool pool);


#ifdef __cplusplus
}
#endif

#endif

