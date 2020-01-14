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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <dps/dps.h>
#include <dps/discovery.h>
#include <dps/private/node.h>
#include <dps/private/cbor.h>
#include <dps/private/pub.h>
#include <dps/private/sub.h>
#include <dps/private/ack.h>
#include <dps/private/io_buf.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static const char* discoveryPrefix = "$DPS_Discovery/";

static DPS_Status EncodeInterests(DPS_Node* node, uint8_t msgType, const DPS_UUID* pubUUID, DPS_TxBuffer* buf)
{
    DPS_Status ret;
    size_t len = 0;
    size_t numEntries = 1;

    DPS_DBGTRACE();

    if (msgType == DPS_MSG_TYPE_ACK) {
        ++numEntries;
        len += CBOR_SIZEOF(uint8_t) + CBOR_SIZEOF_BYTES(sizeof(DPS_UUID));
    }
    len += CBOR_SIZEOF(uint8_t) + DPS_BitVectorSerializedSize(&node->interests);
    len += CBOR_SIZEOF_MAP(numEntries);

    buf->base = DPS_Malloc(len, DPS_ALLOC_BRIEF);
    buf->eob = buf->base + len;
    buf->txPos = buf->base;

    ret = CBOR_EncodeMap(buf, numEntries);
    if (ret != DPS_OK) {
        return ret;
    }
    if (msgType == DPS_MSG_TYPE_ACK) {
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUint8(buf, DPS_CBOR_KEY_PUB_ID);
        }
        if (ret == DPS_OK) {
            ret = CBOR_EncodeUUID(buf, pubUUID);
        }
    }
    if (ret == DPS_OK) {
        ret = CBOR_EncodeUint8(buf, DPS_CBOR_KEY_INTERESTS);
    }
    if (ret == DPS_OK) {
        ret = DPS_BitVectorSerialize(&node->interests, buf);
    }
    return ret;
}

static void OnPub(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_PRINT("Received matching publication %d bytes\n", len);

    if (pub->ackRequested) {
        DPS_Status ret;
        DPS_TxBuffer buf;

        /*
         * TODO - don't ACK our own publication
         */
        DPS_PRINT("Ack was requested\n");
        ret = EncodeInterests(sub->node, DPS_MSG_TYPE_ACK, &pub->pubId, &buf);
        if (ret == DPS_OK) {
            ret = DPS_AckPublication(pub, buf.base, DPS_TxBufferUsed(&buf));
            DPS_Free(buf.base, DPS_ALLOC_BRIEF);
        }
        if (ret != DPS_OK) {
            DPS_PRINT("Ack failed %s\n", DPS_ErrTxt(ret));
        }
    }
}

static void PubSendComplete(DPS_Publication* pub, const uint8_t* data, DPS_Status status)
{
    DPS_DBGTRACE();
    DPS_Free((void*)data, DPS_ALLOC_BRIEF);
}

static DPS_Status SendDiscoveryProbe(DPS_Node* node)
{
    DPS_Status ret;
    DPS_TxBuffer buf;

    DPS_DBGTRACE();
    ret = EncodeInterests(node, DPS_MSG_TYPE_PUB, &node->discoveryPub->pubId, &buf);
    if (ret == DPS_OK) {
        ret = DPS_Publish(node->discoveryPub, NULL, buf.base, DPS_TxBufferUsed(&buf), 0, PubSendComplete);
        if (ret != DPS_OK) {
            DPS_Free(buf.base, DPS_ALLOC_BRIEF);
        }
    } else {
        DPS_PRINT("EncodeInterests failed %s\n", DPS_ErrTxt(ret));
    }
    return ret;
}

static void OnAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_DBGTRACE();
}

DPS_Status DPS_MakeDiscoverable(DPS_Node* node, const char* serviceId)
{
    DPS_Status ret;
    char* topic = NULL;

    DPS_DBGTRACE();

    if (!node) {
        return DPS_ERR_NULL;
    }
    /* Function is idempotent */
    if (node->discoverySub) {
        return DPS_OK;
    }
    /* Use default service id if one is not supplied */
    if (!serviceId) {
        serviceId = "generic_discovery";
    }
    topic = DPS_Malloc(strlen(serviceId) + strlen(discoveryPrefix) + 1, DPS_ALLOC_BRIEF);
    if (!topic) {
        return DPS_ERR_RESOURCES;
    }
    strcpy(topic, discoveryPrefix);
    strcat(topic, serviceId);

    DPS_DBGPRINT("ServiceId = %s\n", topic);

    node->discoverySub = DPS_InitSubscription(node, (const char**)&topic, 1);
    if (!node->discoverySub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    node->discoveryPub = DPS_InitPublication(node, (const char**)&topic, 1, DPS_FALSE, NULL, OnAck);
    if (!node->discoveryPub) {
        ret = DPS_ERR_RESOURCES;
        goto Exit;
    }
    ret = DPS_Subscribe(node->discoverySub, OnPub, NULL);
    if (ret != DPS_OK) {
        goto Exit;
    }
    ret = SendDiscoveryProbe(node);
    if (ret != DPS_OK) {
        goto Exit;
    }

Exit:

    if (topic) {
        DPS_Free(topic, DPS_ALLOC_BRIEF);
    }
    if (ret != DPS_OK) {
        DPS_DestroyPublication(node->discoveryPub);
        node->discoveryPub = NULL;
        DPS_DestroySubscription(node->discoverySub);
        node->discoverySub = NULL;
    }
    return ret;
}

void DPS_MakeNondiscoverable(DPS_Node* node)
{
    DPS_DBGTRACE();
    if (node->discoveryPub) {
        DPS_DestroyPublication(node->discoveryPub);
        node->discoveryPub = NULL;
    }
    if (node->discoverySub) {
        DPS_DestroySubscription(node->discoverySub);
        node->discoverySub = NULL;
    }
}
