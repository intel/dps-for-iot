#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <uv.h>
#include <network.h>
#include <coap.h>
#include <cbor.h>

static ssize_t OnData(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    size_t pktLen;
    DPS_Status ret;

    if (data && len) {
        printf("Received %d bytes\n", len);
    }

    ret = CoAP_GetPktLen(COAP_OVER_TCP, data, len, &pktLen);
    if (ret == DPS_OK) {
        DPS_Buffer payload;
        CoAP_Parsed coap;
        if (len < pktLen) {
            /*
             * Need more data
             */
            return pktLen - len;
        }
        ret = CoAP_Parse(COAP_OVER_TCP, data, len, &coap, &payload);
        if (ret == DPS_OK) {
            uint8_t* addr;
            char* str;
            size_t len;
            size_t i;
            printf("Received CoAP packet type:%d code:%d\n", coap.type, coap.code);
            for (i = 0; i < coap.numOpts; ++i) {
                CoAP_DumpOpt(&coap.opts[i]);
            }
            CBOR_DecodeBytes(&payload, &addr, &len);
            assert(len == 16);
            CBOR_DecodeString(&payload, &str, &len);
            printf("%s\n", str);
            CoAP_Free(&coap);
            return 0;
        } else {
            printf("CoAP_Parse failed: ret= %d\n", ret);
            return -len;
        }
    }
    if (ret == DPS_ERR_EOD) {
        /*
         * Not enough data to parse length
         */
        return 1;
    }
    /*
     * Indicate we consumed nothing
     */
    return -len;
}

static void Listener(DPS_Node* node)
{
    DPS_NetListener* listener = DPS_NetStartListening(node, 0, OnData);
    assert(listener);
    printf("Listening on port %d\n", DPS_NetGetListenerPort(listener));
}

static void OnSendComplete(DPS_Node* node, const struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status)
{
    printf("OnSendComplete: status = %d\n", status);
    DPS_TerminateNode(node);
}

static const char testData[] = "This is a payload";

static void Sender(DPS_Node* node, int port)
{
    DPS_Status ret;
    DPS_Buffer payload;
    uv_buf_t bufs[3];
    struct sockaddr_in6 addr;
    CoAP_Option opts[2];
    uint8_t* addrPtr;
    
    uv_ip6_addr("::", port, &addr);

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = "distributed_pub_sub";
    opts[0].len = 1 + strlen(opts[0].val);

    DPS_BufferInit(&payload, NULL, sizeof(testData) + 64);
    CBOR_ReserveBytes(&payload, 16, &addrPtr);
    CBOR_EncodeString(&payload, testData);

    ret = CoAP_Compose(COAP_OVER_TCP, bufs, 3, COAP_CODE(COAP_REQUEST, COAP_GET), opts, 1, &payload);
    assert(ret == DPS_OK);

    ret = DPS_NetSend(node, bufs, 3, addrPtr, (const struct sockaddr*)&addr, OnSendComplete);
    assert(ret == DPS_OK);
}

int main(int argc, char** argv)
{
    DPS_Node* node = DPS_InitNode(DPS_FALSE, 0, "/");
    int listener = 0;
    int port = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "-l") == 0) {
            listener = 1;
        } else {
            port = atoi(argv[1]);
        }
    }
    if (listener) {
        Listener(node);
    } else {
        if (port == 0) {
            printf("Need port to connect to\n");
            return 1;
        }
        Sender(node, port);
    }
    return uv_run(DPS_GetLoop(node), UV_RUN_DEFAULT);
}

