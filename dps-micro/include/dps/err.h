/**
 * @file
 * Status codes
 */

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

#ifndef _DPS_ERR_H
#define _DPS_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup status Status
 * Status codes.
 * @{
 */

typedef int DPS_Status; /**< The status code type */

#define DPS_OK                     0 /**< Function succeeded */
#define DPS_ERR_OK                 0 /**< Alias for DPS_OK */
#define DPS_ERR_FAILURE            1 /**< Non-specific failure */
#define DPS_ERR_NULL               2 /**< Invalid null pointer */
#define DPS_ERR_ARGS               3 /**< Invalid argument(s) */
#define DPS_ERR_RESOURCES          4 /**< Resource failure, typically memory allocation */
#define DPS_ERR_READ               5 /**< Read operation failed */
#define DPS_ERR_WRITE              6 /**< Write operation failed */
#define DPS_ERR_TIMEOUT            7 /**< Operation timed out */
#define DPS_ERR_EOD                8 /**< Unexpected end of data */
#define DPS_ERR_OVERFLOW           9 /**< Buffer overflow */
#define DPS_ERR_NETWORK           10 /**< Network or socket error */
#define DPS_ERR_INVALID           11 /**< A value was invalid */
#define DPS_ERR_BUSY              12 /**< Operation cannot be performed right now */
#define DPS_ERR_EXISTS            13 /**< Something not expected was present */
#define DPS_ERR_MISSING           14 /**< Something expected was missing */
#define DPS_ERR_STALE             15 /**< A publication was stale */
#define DPS_ERR_NO_ROUTE          16 /**< There is no route to the requested destination */
#define DPS_ERR_NOT_STARTED       17 /**< Node has not yet been started */
#define DPS_ERR_NOT_INITIALIZED   18 /**< Object has not yet been initialized */
#define DPS_ERR_EXPIRED           19 /**< A remote node has expired */
#define DPS_ERR_UNRESOLVED        20 /**< Name resolution failed */
#define DPS_ERR_NODE_DESTROYED    21 /**< Node has already been destroyed */
#define DPS_ERR_EOF               22 /**< End of file or socket closed */
#define DPS_ERR_NOT_IMPLEMENTED   23 /**< Feature or function not implemented */
#define DPS_ERR_SECURITY          24 /**< A security related error - failure to decrypt or authenticate */
#define DPS_ERR_NOT_ENCRYPTED     25 /**< Payload does not appear to be encrypted */
#define DPS_ERR_STOPPING          26 /**< The current node is stopping */
#define DPS_ERR_RANGE             27 /**< A value is out of range */
#define DPS_ERR_LOST_PRECISION    28 /**< Precision was lost when converting a value */
#define DPS_ERR_NO_DATA           29 /**< There is no data available */

/**
 * The text string representation of the status code.
 *
 * @param s the status code
 *
 * @return the text string representation
 */
const char* DPS_ErrTxt(DPS_Status s);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
