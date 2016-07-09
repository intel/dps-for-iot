
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <network.h>
#include <coap.h>
#include <cbor.h>
#include <uv.h>

static DPS_MulticastReceiver* receiver;
static DPS_MulticastSender* sender;

static int protocol = COAP_OVER_UDP;

static ssize_t ReceiveCB(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len)
{
    DPS_Buffer payload;
    DPS_Status ret;
    CoAP_Parsed coap;

    if (data && len) {
        size_t pktLen;
        ret = CoAP_GetPktLen(protocol, data, len, &pktLen);
        assert(ret == DPS_OK);
        if (pktLen != len) {
            fprintf(stderr, "Base packet length expected %d got %d\n", len, pktLen);
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
            printf("%s\n", payload.pos);
            CoAP_Free(&coap);
        } else {
            printf("CoAP_Parse failed: ret= %d\n", ret);
        }
    }
    return len;
}

static uint8_t buffer[1025];

static void DataSender(uv_idle_t* handle)
{
    DPS_Status ret;
    DPS_Buffer payload;
    uv_buf_t bufs[3];
    size_t len;
    CoAP_Option opts[2];
    uint8_t* addrPtr;

    usleep(1000 * 1000 * 3);

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = "distributed_pub_sub";
    opts[0].len = 1 + strlen(opts[0].val);

    DPS_BufferInit(&payload, buffer, sizeof(buffer));
    CBOR_ReserveBytes(&payload, 16, &addrPtr);

    ret = CoAP_Compose(protocol, bufs, 3, COAP_CODE(COAP_REQUEST, COAP_GET), opts, 1, &payload);
    if (ret != DPS_OK) {
        printf("ComposeCoAP failed ret=%d\n", ret);
    } else {
        ret = DPS_MulticastSend(sender, bufs, 3, addrPtr);
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
