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
#include "queue.h"

void DPS_QueueInit(DPS_Queue* queue)
{
    queue->prev = queue;
    queue->next = queue;
}

int DPS_QueueEmpty(const DPS_Queue* queue)
{
    return queue == queue->next;
}

DPS_Queue* DPS_QueueFront(const DPS_Queue* queue)
{
    return queue->next;
}

DPS_Queue* DPS_QueueBack(const DPS_Queue* queue)
{
    return queue->prev;
}

void DPS_QueuePushBack(DPS_Queue* queue, DPS_Queue* item)
{
    item->next = queue;
    item->prev = queue->prev;
    ((DPS_Queue*)item->prev)->next = item;
    queue->prev = item;
}

void DPS_QueueRemove(DPS_Queue* item)
{
    ((DPS_Queue*)item->prev)->next = item->next;
    ((DPS_Queue*)item->next)->prev = item->prev;
}
