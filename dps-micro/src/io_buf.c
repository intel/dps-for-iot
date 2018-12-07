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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <dps/private/node.h>
#include <dps/private/io_buf.h>

void DPS_RxBufferInit(DPS_RxBuffer* buffer, uint8_t* storage, size_t size)
{
    assert(storage);
    buffer->base = storage;
    buffer->rxPos = storage;
    buffer->eod = storage + size;
}

static void DPS_TxBufferInit(DPS_TxBuffer* buffer, uint8_t* storage, size_t size)
{
    assert(storage);
    buffer->base = storage;
    buffer->txPos = storage;
    buffer->eob = storage + size;
}

DPS_Status DPS_TxBufferAppend(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    if (data && len) {
        memcpy(buffer->txPos, data, len);
        buffer->txPos += len;
    }
    return DPS_OK;
}

/*
 * TODO - allow space to reserved at the front of a buffer to avoid having
 *        to do the memmove to create space.
 */
DPS_Status DPS_TxBufferPrepend(DPS_TxBuffer* buffer, size_t len, uint8_t** pos)
{
    if (len > DPS_TxBufferSpace(buffer)) {
        return DPS_ERR_RESOURCES;
    }
    *pos = buffer->base;
    memmove(buffer->base, buffer->base + len, DPS_TxBufferUsed(buffer));
    return DPS_OK;
}

void DPS_TxBufferToRx(const DPS_TxBuffer* txBuffer, DPS_RxBuffer* rxBuffer)
{
    assert(txBuffer && rxBuffer);
    rxBuffer->base = txBuffer->base;
    rxBuffer->eod = txBuffer->txPos;
    rxBuffer->rxPos = txBuffer->base;
}

void DPS_RxBufferToTx(const DPS_RxBuffer* rxBuffer, DPS_TxBuffer* txBuffer)
{
    assert(rxBuffer && txBuffer);
    txBuffer->base = rxBuffer->base;
    txBuffer->eob = rxBuffer->eod;
    txBuffer->txPos = rxBuffer->eod;
}

DPS_Status DPS_TxBufferReserve(DPS_Node* node, DPS_TxBuffer* buf, size_t len, DPS_BUFFER_POOL pool)
{
    switch (pool) {
    case DPS_TX_POOL:
        if ((len + node->txLen) > DPS_TX_BUFFER_SIZE) {
            return DPS_ERR_RESOURCES;
        }
        DPS_TxBufferInit(buf, &node->txBuffer[node->txLen + DPS_TX_HEADER_SIZE], len);
        node->txLen += len;
        break;
    case DPS_TX_HDR_POOL:
        if ((len + node->txHdrLen) > DPS_TX_HEADER_SIZE) {
            return DPS_ERR_RESOURCES;
        }
        node->txHdrLen += len;
        DPS_TxBufferInit(buf, node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen, len);
        break;
    case DPS_TMP_POOL:
        if ((len + node->tmpLen) > DPS_TMP_BUFFER_SIZE) {
            return DPS_ERR_RESOURCES;
        }
        DPS_TxBufferInit(buf, &node->tmpBuffer[node->tmpLen], len);
        node->tmpLen += len;
        break;
    default:
        return DPS_ERR_ARGS;
    }
    buf->pool = pool;
    buf->node = node;
    return DPS_OK;
}

void DPS_TxBufferCommit(DPS_TxBuffer* buf)
{
    switch (buf->pool) {
    case DPS_TX_POOL:
        buf->node->txLen -= DPS_TxBufferSpace(buf);
        break;
    case DPS_TX_HDR_POOL:
        assert(DPS_TxBufferSpace(buf) == 0);
        break;
    case DPS_TMP_POOL:
        buf->node->tmpLen -= DPS_TxBufferSpace(buf);
        break;
    default:
        assert(DPS_FALSE);
        break;
    }
}

void DPS_TxBufferFreePools(DPS_Node* node)
{
    node->txLen = 0;
    node->txHdrLen = 0;
    node->tmpLen = 0;
}
