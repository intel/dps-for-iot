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

#include <dps/dps.h>
#include <dps/private/node.h>
#include <dps/private/dps.h>
#include <dps/private/network.h>
#include <dps/private/cbor.h>
#include <dps/private/coap.h>
#include <dps/private/pub.h>
#include <dps/uuid.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

static DPS_Node node;

static DPS_Status DecodeRequest(DPS_Node* node, DPS_RxBuffer* buf)
{
    DPS_Status ret;
    uint8_t msgVersion;
    uint8_t msgType;
    size_t len;

    /* Free the temporary pool */
    DPS_TxBufferFreePool(node, DPS_TMP_POOL);

    CBOR_Dump("Request in", buf->rxPos, DPS_RxBufferAvail(buf));
    ret = CBOR_DecodeArray(buf, &len);
    if (ret != DPS_OK || (len != 5)) {
        DPS_ERRPRINT("Expected a CBOR array of 5 elements\n");
        return ret;
    }
    ret = CBOR_DecodeUint8(buf, &msgVersion);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Expected a message type\n");
        return ret;
    }
    if (msgVersion != DPS_MSG_VERSION) {
        DPS_ERRPRINT("Expected message version %d, received %d\n", DPS_MSG_VERSION, msgVersion);
        return DPS_ERR_NOT_IMPLEMENTED;
    }
    ret = CBOR_DecodeUint8(buf, &msgType);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("Expected a message type\n");
        return ret;
    }
    ret = DPS_ERR_INVALID;
    switch (msgType) {
    case DPS_MSG_TYPE_PUB:
        ret = DPS_DecodePublication(node, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodePublication returned %s\n", DPS_ErrTxt(ret));
        }
        break;
#if 0
    case DPS_MSG_TYPE_ACK:
        ret = DPS_DecodeAcknowledgement(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DPS_DecodeAcknowledgement returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_SUB:
        ret = DPS_DecodeSubscription(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DecodeSubscription returned %s\n", DPS_ErrTxt(ret));
        }
        break;
    case DPS_MSG_TYPE_SAK:
        ret = DPS_DecodeSubscriptionAck(node, ep, buf);
        if (ret != DPS_OK) {
            DPS_DBGPRINT("DPS_DecodeSubscriptionAck returned %s\n", DPS_ErrTxt(ret));
        }
        break;
#endif
    default:
        DPS_ERRPRINT("Invalid message type\n");
        break;
    }
    /*
     * Stale is not a network or invalid message error, so don't
     * report an error to the transport.
     */
    if (ret == DPS_ERR_STALE) {
        ret = DPS_OK;
    }
    return ret;
}

static DPS_Status OnMcastReceive(DPS_Node* node, DPS_RxBuffer* rxBuf, DPS_Status status)
{
    DPS_Status ret;
    CoAP_Parsed coap;
    DPS_DBGTRACEA("Received %d bytes\n%s\n", DPS_RxBufferAvail(rxBuf), rxBuf->base);

    ret = CoAP_Parse(rxBuf->base, DPS_RxBufferAvail(rxBuf), &coap, rxBuf);
    if (ret == DPS_OK) {
        ret = DecodeRequest(node, rxBuf);
    }
    return ret;
}

DPS_Node* DPS_CreateNode(const char* separators)
{
    memset(&node, 0, sizeof(node));
    node.separators = separators;
    node.keyStore = DPS_CreateKeyStore();
    return &node;
}

DPS_Status DPS_Start(DPS_Node* node)
{
    DPS_Status status;

    DPS_DBGTRACE();

    if (!node->keyStore) {
        return DPS_ERR_INVALID;
    }
    status = DPS_NetworkInit(node);
    if (status != DPS_OK) {
        return status;
    }
    status = DPS_MCastStart(node, OnMcastReceive);
    if (status != DPS_OK) {
        return status;
    }

    return DPS_OK;
}

DPS_KeyStore* DPS_GetKeyStore(DPS_Node* node)
{
    return node ? node->keyStore : NULL;
}

void DPS_DestroyNode(DPS_Node* node)
{
    if (node) {
        DPS_DestroyKeyStore(node->keyStore);
    }
}

void DPS_MakeNonce(const DPS_UUID* uuid, uint32_t seqNum, uint8_t msgType, uint8_t nonce[COSE_NONCE_LEN])
{
    uint8_t* p = nonce;

    *p++ = (uint8_t)(seqNum >> 0);
    *p++ = (uint8_t)(seqNum >> 8);
    *p++ = (uint8_t)(seqNum >> 16);
    *p++ = (uint8_t)(seqNum >> 24);
    memcpy(p, uuid, COSE_NONCE_LEN - sizeof(uint32_t));
    /*
     * Adjust one bit so nonce for PUB's and ACK's for same pub id and sequence number are different
     */
    if (msgType == DPS_MSG_TYPE_PUB) {
        p[0] &= 0x7F;
    } else {
        p[0] |= 0x80;
    }
}
