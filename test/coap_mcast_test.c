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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <uv.h>
#include <unistd.h>
#include <dps/private/network.h>
#include "coap.h"
#include <dps/private/cbor.h>

static DPS_MulticastReceiver* receiver;
static DPS_MulticastSender* sender;

static int protocol = COAP_OVER_UDP;

static DPS_Status ReceiveCB(DPS_Node* node, DPS_NetEndpoint* ep, DPS_Status status, const uint8_t* data, size_t len)
{
    DPS_RxBuffer payload;
    DPS_Status ret = DPS_OK;
    CoAP_Parsed coap;

    if (data && len) {
        size_t pktLen;
        ret = CoAP_GetPktLen(protocol, data, len, &pktLen);
        assert(ret == DPS_OK);
        if (pktLen != len) {
            fprintf(stderr, "Base packet length expected %zu got %zu\n", len, pktLen);
            assert(pktLen == len);
        }
        ret = CoAP_Parse(protocol, data, len, &coap, &payload);
        if (ret == DPS_OK) {
            uint8_t* addr;
            size_t l;
            size_t i;
            printf("Received CoAP packet type:%d code:%d\n", coap.type, coap.code);
            for (i = 0; i < coap.numOpts; ++i) {
                CoAP_DumpOpt(&coap.opts[i]);
            }
            ret = CBOR_DecodeBytes(&payload, &addr, &l);
            assert(ret == DPS_OK);
            assert(l == 16);
            printf("%s\n", payload.rxPos);
            CoAP_Free(&coap);
        } else {
            printf("CoAP_Parse failed: ret= %d\n", ret);
        }
    }
    return ret;
}

static uint8_t buffer[1025];

static void DataSender(uv_idle_t* handle)
{
    DPS_Status ret;
    DPS_TxBuffer headers;
    DPS_TxBuffer payload;
    size_t len;
    CoAP_Option opts[2];

    usleep(1000 * 1000 * 3);

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = "distributed_pub_sub";
    opts[0].len = 1 + strlen(opts[0].val);

    DPS_TxBufferInit(&payload, buffer, sizeof(buffer));

    ret = CoAP_Compose(protocol, COAP_CODE(COAP_REQUEST, COAP_GET), opts, 1, DPS_TxBufferUsed(&payload), &headers);
    if (ret != DPS_OK) {
        printf("ComposeCoAP failed ret=%d\n", ret);
    } else {
        uv_buf_t bufs[] = {
            { (char*)headers.base, DPS_TxBufferUsed(&headers) },
            { (char*)payload.base, DPS_TxBufferUsed(&payload) }
        };
        ret = DPS_MulticastSend(sender, bufs, 3);
        if (ret != DPS_OK) {
            fprintf(stderr, "DPS_MulticastSend failed ret=%d\n", ret);
        }
    }
}

static void SendLoop()
{
    uv_idle_t idler;

    uv_idle_init(uv_default_loop(), &idler);
    uv_idle_start(&idler, DataSender);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

int main(int argc, char** argv)
{
    int i;

    if (argc > 1) {
        /*
         * Allows s app to be used for testing of CoAP over TCP serialization
         */
        if (strcmp(argv[1], "tcp") == 0) {
            protocol = COAP_OVER_TCP;
        }
    }
    for (i = 0; i < sizeof(buffer); ++i) {
        buffer[i] = 'a' + i % 26;
    }
    buffer[sizeof(buffer) - 1] = 0;

    receiver = DPS_MulticastStartReceive(NULL, ReceiveCB);
    assert(receiver);
    sender = DPS_MulticastStartSend(NULL);
    assert(sender);
    SendLoop();

    return 0;
}
