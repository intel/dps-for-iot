/**
 * @file
 * Generic queue
 */

/*
 *******************************************************************
 *
 * Copyright 2019 Intel Corporation All rights reserved.
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

#ifndef _QUEUE_H
#define _QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generic queue
 */
typedef struct _DPS_Queue {
    void* prev;                 /**< Previous queue item */
    void* next;                 /**< Next queue item */
} DPS_Queue;

/**
 * Initializes a queue
 *
 * @param queue the queue
 */
void DPS_QueueInit(DPS_Queue* queue);

/**
 * Returns whether the queue is empty or not.
 *
 * @param queue the queue
 *
 * @return DPS_TRUE if empty, DPS_FALSE otherwise
 */
int DPS_QueueEmpty(const DPS_Queue* queue);

/**
 * Returns the item at the front of the queue.
 *
 * @param queue the queue
 *
 * @return the item at the front of the queue
 */
DPS_Queue* DPS_QueueFront(const DPS_Queue* queue);

/**
 * Pushes an item onto the back of the queue
 *
 * @param queue the queue
 * @param item the item
 */
void DPS_QueuePushBack(DPS_Queue* queue, DPS_Queue* item);

/**
 * Removes an item from the queue it is in.
 *
 * @param item the item
 */
void DPS_QueueRemove(DPS_Queue* item);

#ifdef __cplusplus
}
#endif

#endif
