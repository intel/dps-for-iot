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

#ifndef _DPS_INTERNAL_H
#define _DPS_INTERNAL_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DPS_SECS_TO_MS(t)   ((uint64_t)(t) * 1000ull)
#define DPS_MS_TO_SECS(t)   ((uint32_t)((t) / 1000ull))

/**
 * Address type
 */
typedef struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
} DPS_NodeAddress;


/**
 * For passing buffers around
 */
typedef struct {
    uint8_t* base; /**< base address for buffer */
    uint8_t* eod;  /**< end of buffer or data */
    uint8_t* pos;  /**< current read/write location in buffer */
} DPS_Buffer;

/**
 * Initialize a buffer struct
 *
 * @param buffer    Buffer to initialized
 * @param storage   The storage for the buffer. If the storage is NULL storage is allocated.
 * @param size      Current size of the buffer
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if storage is needed and could not be allocated.
 */
DPS_Status DPS_BufferInit(DPS_Buffer* buffer, uint8_t* storage, size_t size);

/**
 * Free resources allocated for a buffer and nul out the buffer pointers.
 *
 * @param buffer    Buffer to free
 */
void DPS_BufferFree(DPS_Buffer* buffer);

/**
 * Add data to a buffer
 *
 * @param buffer   Buffer to append to
 * @param storage  The data to append
 * @param len      Length of the data to append
 *
 * @return   DPS_OK or DP_ERR_RESOURCES if there not enough room in the buffer
 */
DPS_Status DPS_BufferAppend(DPS_Buffer* buffer, const uint8_t* data, size_t len);

/*
 * Rewind a buffer
 */
#define DPS_BufferRewind(b) do { (b)->eod = (b)->pos; (b)->pos = (b)->base; } while (0)

/*
 * Set the end of a buffer
 */
#define DPS_BufferSeekEnd(b) do { (b)->pos = (b)->eod; } while (0)

/*
 * Space left in an output buffer
 */
#define DPS_BufferSpace(b)  ((size_t)((b)->eod - (b)->pos))

/*
 * Data available in an input buffer
 */
#define DPS_BufferAvail(b)  ((size_t)((b)->eod - (b)->pos))

/*
 * Number of bytes currently in an output buffer
 */
#define DPS_BufferUsed(b)  ((size_t)((b)->pos - (b)->base))

/**
 * Print the current subscriptions
 */
void DPS_DumpSubscriptions(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif
