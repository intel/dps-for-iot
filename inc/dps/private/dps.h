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

/*
 * Reset the buffer pointers to the initialized state
 */
#define DPS_BufferReset(b)  ((size_t)((b)->pos = (b)->base))

/*
 * Space left in a buffer being written
 */
#define DPS_BufferSpace(b)  ((size_t)((b)->eod - (b)->pos))

/*
 * Data available in a buffer being read
 */
#define DPS_BufferAvail(b)  ((size_t)((b)->eod - (b)->pos))

/*
 * Space currently used in buffer
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
