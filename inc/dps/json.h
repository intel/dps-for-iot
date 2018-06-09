/**
 * @file
 * JSON <-> CBOR conversion
 */

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

#ifndef _DPS_JSON_H
#define _DPS_JSON_H

#include <stdint.h>
#include <dps/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup json JSON
 * Convert between JSON and CBOR
 * @{
 */

/**
 * Generate a CBOR encoded byte array from a JSON string. Note that if there are multiple
 * JSON elements in the input string only the first one is parsed and anything after the
 * fist element is ignored.
 *
 * @param json     NUL terminated JSON string to convert
 * @param cbor     Destination buffer for the conversion
 * @param cborSize The size of the cbor buffer
 * @param cborLen  Returns the number of CBOR bytes written 
 *
 * @return
 *         - DPS_OK if the conversion was successful
 *         - DPS_ERR_OVERFLOW if the cbor buffer was too small
 *         - DPS_ERR_INVALID if the input was not valid JSON
 *         - other error status codes
 */
DPS_Status DPS_JSON2CBOR(const char* json, uint8_t* cbor, size_t cborSize, size_t* cborLen);

/**
 * Generate a JSON string from a CBOR encoded byte array.
 *
 * @param cbor     CBOR encoded source data for the conversion
 * @param cborLen  The length of the CBOR data
 * @param json     Destination buffer for generated JSON string
 * @param jsonSize The length of the JSON string buffer
 * @param pretty   If TRUE format the JSON using indentation and newlines, if FALSE
 *                 the output is compact with no newlines or whitespace is inserted.
 *
 * @return
 *         - DPS_OK if the conversion was successful
 *         - DPS_ERR_OVERFLOW if the json buffer was too small
 *         - DPS_ERR_INVALID if the input was not valid CBOR
 *         - other error status codes
 */
DPS_Status DPS_CBOR2JSON(const uint8_t* cbor, size_t cborLen, char* json, size_t jsonSize, int pretty);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
