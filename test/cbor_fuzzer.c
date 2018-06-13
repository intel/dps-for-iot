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

#include "test.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
    DPS_RxBuffer buf;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u;
    int8_t i8;
    int16_t i16;
    int32_t i32;
    int64_t i;
    float f;
    double d;
    size_t sz;
    int b;
    uint8_t* bytes;
    char* str;
    CBOR_MapState map;
    int32_t keys[] = { 1, 2 };

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeUint8(&buf, &u8);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeUint16(&buf, &u16);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeUint32(&buf, &u32);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeUint(&buf, &u);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeInt8(&buf, &i8);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeInt16(&buf, &i16);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeInt32(&buf, &i32);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeInt(&buf, &i);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeFloat(&buf, &f);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeDouble(&buf, &d);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeMap(&buf, &sz);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeTag(&buf, &u);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeBoolean(&buf, &b);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeBytes(&buf, &bytes, &sz);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeString(&buf, &str, &sz);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_DecodeArray(&buf, &sz);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_Skip(&buf, &u8, &sz);
    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    CBOR_Peek(&buf, &u8, NULL);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    DPS_ParseMapInit(&map, &buf, keys, A_SIZEOF(keys), NULL, 0);
    while (DPS_ParseMapNext(&map, &i32) == DPS_OK) {
        CBOR_Skip(&buf, &u8, &sz);
    }
    DPS_ParseMapDone(&map);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    DPS_ParseMapInit(&map, &buf, NULL, 0, keys, A_SIZEOF(keys));
    while (DPS_ParseMapNext(&map, &i32) == DPS_OK) {
        CBOR_Skip(&buf, &u8, &sz);
    }
    DPS_ParseMapDone(&map);

    DPS_RxBufferInit(&buf, (uint8_t*)data, len);
    DPS_ParseMapInit(&map, &buf, keys, A_SIZEOF(keys), keys, A_SIZEOF(keys));
    while (DPS_ParseMapNext(&map, &i32) == DPS_OK) {
        CBOR_Skip(&buf, &u8, &sz);
    }
    DPS_ParseMapDone(&map);

    return 0;
}
