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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dps/dbg.h>
#include <dps/private/coap.h>
#include <dps/private/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);

static int ParseOpt(const uint8_t* buf, size_t bufLen, int prevOpt, CoAP_Option* opt)
{
    const uint8_t* head = buf;
    uint8_t lFlag = head[0] & 0xF;
    uint8_t dFlag = head[0] >> 4;

    if (bufLen < 2) {
        return -1;
    }
    if (dFlag == 0xF || lFlag == 0xF) {
        return 0;
    }
    buf += 1;
    bufLen -= 1;
    if (dFlag < 13) {
        opt->id = prevOpt + dFlag;
    } else if (dFlag == 13) {
        opt->id = 13 + prevOpt + buf[0];
        buf += 1;
        bufLen -= 1;
    } else {
        if (bufLen < 2) {
            return -1;
        }
        opt->id = 269 + prevOpt + (buf[0] << 8) + buf[1];
        buf += 2;
        bufLen -= 2;
    }
    if (lFlag < 13) {
        opt->len = lFlag;
    } else if (lFlag == 13) {
        if (bufLen < 1) {
            return -1;
        }
        opt->len = 13 + buf[0];
        buf += 1;
        bufLen -= 1;
    } else {
        if (bufLen < 2) {
            return -1;
        }
        opt->len = 269 + (buf[0] << 8) + buf[1];
        buf += 2;
        bufLen -= 2;
    }
    if (bufLen < opt->len) {
        return -1;
    }
    opt->val = buf;
    return (int)(opt->len + (buf - head));
}

void CoAP_Free(CoAP_Parsed* coap)
{
    memset(coap, 0, sizeof(coap));
}

DPS_Status CoAP_Parse(const uint8_t* buffer, size_t bufLen, CoAP_Parsed* coap, DPS_RxBuffer* payload)
{
    const uint8_t* p;
    size_t len;
    int prevOptId = 0;

    if (bufLen < 5) {
        return DPS_ERR_RESOURCES;
    }
    coap->version = buffer[0] >> 6;
    coap->type = buffer[0] >> 4 & 0x3;
    coap->tokenLen = buffer[0] & 0xF;
    coap->code = buffer[1];
    coap->msgId = buffer[2] << 8 | buffer[3];
    bufLen -= 4;
    buffer += 4;
    if (bufLen < coap->tokenLen) {
        return DPS_ERR_INVALID;
    }
    if (coap->tokenLen) {
        if (coap->tokenLen > sizeof(coap->token)) {
            return DPS_ERR_INVALID;
        }
        memcpy(coap->token, buffer, coap->tokenLen);
        bufLen -= coap->tokenLen;
        buffer += coap->tokenLen;
    }
    /*
     * Parse opts
     */
    coap->numOpts = 0;
    p = buffer;
    len = bufLen;
    while (len) {
        int optSize;
        if (coap->numOpts == COAP_MAX_OPTS) {
            return DPS_ERR_INVALID;
        }
        optSize = ParseOpt(p, len, prevOptId, &coap->opts[coap->numOpts]);
        if (optSize == 0) {
            break;
        }
        if (optSize < 0) {
            return DPS_ERR_INVALID;
        }
        prevOptId = coap->opts[coap->numOpts].id;
        len -= optSize;
        p += optSize;
        ++coap->numOpts;
    }
    /*
     * If we are at the end of the buffer there is no payload
     */
    if (len == 0) {
        DPS_RxBufferInit(payload, NULL, 0);
        return DPS_OK;
    }
    /*
     * We expect an end-of-options marker followed by at least one payload byte
     */
    if (len < 2 || p[0] != COAP_END_OF_OPTS) {
        return DPS_ERR_EOD;
    }
    /*
     * Everything else is payload
     */
    DPS_RxBufferInit(payload, (uint8_t*)(p + 1), len -1);

    return DPS_OK;
}


static size_t CoAP_OptLen(uint8_t code, const char* token, const CoAP_Option* opts, size_t numOpts, size_t payloadLen)
{
    size_t i;
    uint8_t tokenLen = (uint8_t)strnlen(token, COAP_MAX_TOKEN_LEN);
    size_t optLen = 0;
    uint8_t optIdLast = 0;

    /*
     * Calculate the total length of options
     */
    for (i = 0; i < numOpts; ++i) {
        uint16_t delta = opts[i].id - optIdLast;
        size_t len = opts[i].len;
        if (opts[i].id < optIdLast) {
            DPS_ERRPRINT("Options ids must be in ascending order %d < %d\n", opts[i].id, optIdLast);
            return 0;
        }
        optLen += (len + 1);
        if (delta > 13) {
            ++optLen;
            if (delta > 269) {
                ++optLen;
            }
        }
        if (len > 13) {
            ++optLen;
            if (len > 269) {
                ++optLen;
            }
        }
        optIdLast += delta;
    }
    if (payloadLen > 0) {
        ++optLen;
    }
    return optLen + tokenLen + 4;
}

static DPS_Status CoAP_Compose(uint8_t code, const char* token, const CoAP_Option* opts, size_t numOpts, size_t optLen, size_t payloadLen, DPS_TxBuffer* buf)
{
    static uint16_t msgId = 1;
    uint8_t optIdLast = 0;
    uint8_t tokenLen = (uint8_t)strnlen(token, COAP_MAX_TOKEN_LEN);
    DPS_Status ret = DPS_OK;
    
    if (tokenLen > COAP_MAX_TOKEN_LEN) {
        return DPS_ERR_INVALID;
    }
    /*
     * Compose the header
     */
    *buf->txPos++ = COAP_VERSION << 6 | (COAP_TYPE_NON_CONFIRMABLE << 4) | tokenLen;
    *buf->txPos++ = code;
    *buf->txPos++ = msgId >> 8;
    *buf->txPos++ = msgId & 0xFF;
    ++msgId;
    /*
     * Write the token if there is one
     */
    if (tokenLen) {
        if (tokenLen > DPS_TxBufferSpace(buf)) {
            return DPS_ERR_RESOURCES;
        }
        memcpy(buf->txPos, token, tokenLen);
        buf->txPos += tokenLen;
    }
    /*
     * Write the options
     */
    while (numOpts--) {
        uint16_t delta = opts->id - optIdLast;
        size_t len = opts->len;
        uint8_t* optHead = buf->txPos++;
        /*
         * Three different option encodings
         */
        if (delta < 13) {
            *optHead = (uint8_t)(delta << 4);
        } else if (delta < 269) {
            delta -= 13;
            *optHead = (uint8_t)(13 << 4);
            *buf->txPos++ = (uint8_t)(delta);
        } else {
            delta -= 269;
            *optHead = (uint8_t)(14 << 4);
            *buf->txPos++ = (uint8_t)(delta >> 8);
            *buf->txPos++ = (uint8_t)(delta & 0xFF);
        }
        /*
         * Three different length encodings
         */
        if (len < 13) {
            *optHead |= (uint8_t)len;
        } else if (len < 269) {
            len -= 13;
            *optHead |= (uint8_t)13;
            *buf->txPos++ = (uint8_t)(len);
        } else {
            len -= 269;
            *optHead |= (uint8_t)14;
            *buf->txPos++ = (uint8_t)(len >> 8);
            *buf->txPos++ = (uint8_t)(len & 0xFF);
        }
        if (opts->val && opts->len) {
            if (opts->len > DPS_TxBufferSpace(buf)) {
                return DPS_ERR_RESOURCES;
            }
            memcpy(buf->txPos,  opts->val, opts->len);
            buf->txPos += opts->len;
        }
        optIdLast += delta;
        ++opts;
    }
    if (payloadLen > 0) {
        *buf->txPos++ = COAP_END_OF_OPTS;
    }
    DPS_DBGPRINT("CoAP header %d bytes\n", DPS_TxBufferUsed(buf));
    assert(DPS_TxBufferUsed(buf) == optLen);
    return ret;
}

static const char DPS_PublicationURI[] = "dps/pub";
static const uint8_t DPS_ContentFormat = COAP_FORMAT_APPLICATION_CBOR;

#define NUM_OPTS 2

DPS_Status CoAP_InsertHeader(DPS_Node* node, size_t payloadLen)
{
    DPS_Status ret;
    DPS_TxBuffer coap;
    size_t optLen;
    CoAP_Option opts[NUM_OPTS];

    opts[0].id = COAP_OPT_URI_PATH;
    opts[0].val = (uint8_t*)DPS_PublicationURI;
    opts[0].len = sizeof(DPS_PublicationURI);
    opts[1].id = COAP_OPT_CONTENT_FORMAT;
    opts[1].val = (uint8_t*)&DPS_ContentFormat;
    opts[1].len = sizeof(DPS_ContentFormat);

    optLen = CoAP_OptLen(COAP_CODE(COAP_REQUEST, COAP_PUT), "", opts, NUM_OPTS, payloadLen);
    if (optLen == 0) {
        return DPS_ERR_INVALID;
    }
    /* Allocate space in the header pool */
    ret = DPS_TxBufferReserve(node, &coap, optLen, DPS_TX_HDR_POOL);
    if (ret == DPS_OK) {
        ret =  CoAP_Compose(COAP_CODE(COAP_REQUEST, COAP_PUT), "", opts, NUM_OPTS, optLen, payloadLen, &coap);
    }
    if (ret == DPS_OK) {
        DPS_TxBufferCommit(&coap);
    }
    return ret;
}
