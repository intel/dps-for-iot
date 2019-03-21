/**
 * @file
 * A registration service
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

#ifndef _DPS_REGISTRATION_H
#define _DPS_REGISTRATION_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup services Services
 * Services built upon DPS.
 * @{
 */

/**
 * @defgroup registration Registration
 * A registration service.
 * @{
 */

#define DPS_REGISTRATION_PUT_TIMEOUT 2000 /**< Default 2 second timeout for put requests */
#define DPS_REGISTRATION_GET_TIMEOUT 5000 /**< Default 5 second timeout for get requests */

/** The registry topic string */
extern const char* DPS_RegistryTopicString;

/*
 * Registration entry flags
 */
#define DPS_CANDIDATE_TRYING   0x01  /**< An attempt is being made link to a candidate */
#define DPS_CANDIDATE_FAILED   0x02  /**< An attempt to link to a candidate was attempted but failed */
#define DPS_CANDIDATE_LINKED   0x04  /**< Registration is currently linked */
#define DPS_CANDIDATE_UNLINKED 0x08  /**< Registration was linked but is currently not linked */
#define DPS_CANDIDATE_INVALID  0x10  /**< This is a invalid candidate address for linking */

/**
 * Registration entry
 */
typedef struct _DPS_Registration {
    uint8_t flags; /**< Registration entry flags */
    char* addrText; /**< The registered address text */
} DPS_Registration;

/**
 * For returning a list of candidate remote nodes
 */
typedef struct _DPS_RegistrationList {
    uint8_t size;     /**< Size of the list */
    uint8_t count;    /**< Number of entries currently in the list */
    DPS_Registration list[1]; /**< The list */
} DPS_RegistrationList;

/**
 * Create an empty registration list of the specified size
 *
 * @param size The desired size of the list
 *
 * @return The newly created registration list or NULL if an error occurred
 */
DPS_RegistrationList* DPS_CreateRegistrationList(uint8_t size);

/**
 * Destroy a registration list and free resources
 *
 * @param regs A previously created registration list
 */
void DPS_DestroyRegistrationList(DPS_RegistrationList* regs);

/**
 * Function prototype for callback called when DPS_Registration_Put() completes
 *
 * @param status  Status code indicating success or failure
 *                - DPS_OK if the registration was made
 *                - Other error status codes
 * @param data    Caller supplied data passed into the DPS_Registration_Put()
 *
 */
typedef void (*DPS_OnRegPutComplete)(DPS_Status status, void* data);

/**
 * Register a local node with a registration service.
 *
 * @param node          The local node to register
 * @param addrText      The text string of the registration service address
 * @param tenantString  Topic string identifying the tenant
 * @param timeout       Timeout in milliseconds
 * @param cb            Callback called when the registration completes.
 * @param data          Caller provided data to be passed to the callback function
 *
 * @return DPS_OK if the registration put request was successfully initiated, otherwise returns an
 *         error status and the callback function will not be called.
 */
DPS_Status DPS_Registration_Put(DPS_Node* node, const char* addrText, const char* tenantString,
                                uint16_t timeout, DPS_OnRegPutComplete cb, void* data);

/**
 * Synchronous version of DPS_RegistrationPut(). This function blocks until the operations is
 * complete.
 *
 * @param node          The local node to register
 * @param addrText      The text string of the registration service address
 * @param tenantString  Topic string identifying the tenant
 * @param timeout       Timeout in milliseconds
 *
 * @return DPS_OK if the put request succeeded or and error status for the failure.
 */
DPS_Status DPS_Registration_PutSyn(DPS_Node* node, const char* addrText, const char* tenantString,
                                   uint16_t timeout);

/**
 * Function prototype for callback called when DPS_Registration_Get() completes
 *
 * @param regs   Struct containing the list of candidate passed in to DPS_Registration_Get()
 * @param status DPS_OK if the get completed successfully - the registration list might be empty,
 * @param data   Caller supplied data passed into the DPS_Registration_Get()
 */
typedef void (*DPS_OnRegGetComplete)(DPS_RegistrationList* regs, DPS_Status status, void* data);

/**
 * Lookup the addresses registered with a registration service.
 *
 * @param node          The node
 * @param addrText      The text string of the registration service address
 * @param tenantString  Topic string identifying the tenant
 * @param regs          Registration list for accumulating the results. The count field must be
 *                      initialized with the maximum number of registrations to be returned. The
 *                      candidate list pointer must remain valid until the callback is called.
 * @param timeout       Timeout in milliseconds
 * @param cb            The callback to call with the result
 * @param data          Caller supplied data to be passed to the callback
 *
 * @return DPS_OK if the registration get request was successfully initiated, otherwise returns an
 *         error status and the callback function will not be called.
 */
DPS_Status DPS_Registration_Get(DPS_Node* node, const char* addrText, const char* tenantString,
                                DPS_RegistrationList* regs, uint16_t timeout, DPS_OnRegGetComplete cb,
                                void* data);

/**
 * A synchronous version of DPS_RegistrationGet() this function blocks until the candidate list has
 * been populated or the request times out.
 *
 * @param node          The node
 * @param addrText      The text string of the registration service address
 * @param tenantString  Topic string identifying the tenant
 * @param regs          Registration list for accumulating the results.
 * @param timeout       Timeout in milliseconds
 *
 * @return DPS_OK if the get request succeeded or and error status for the failure.
 */
DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* addrText, const char* tenantString,
                                   DPS_RegistrationList* regs, uint16_t timeout);

/**
 * Function prototype for callback called when DPS_Registration_LinkTo() completes
 *
 * @param regs    The list of registrations addresses passed in to DPS_Registration_LinkTo().
 * @param addr    The address if the remote if status == DPS_OK
 * @param status  Status code indicating success or failure
 *                - DPS_OK if a link was successfully established
 *                - DPS_ERR_NO_ROUTE if a link could not be established
 *                - Other error status codes
 * @param data    Caller supplied data passed into the DPS_Registration_LinkTo()
 *
 */
typedef void (*DPS_OnRegLinkToComplete)(DPS_Node* node, DPS_RegistrationList* regs, const DPS_NodeAddress* addr, DPS_Status status, void* data);

/**
 * Randomly select a remote candidate to link to.
 *
 * @param node  The local node to link
 * @param regs  The list of candidate registrations to try to link to
 * @param cb    The callback to call with the result
 * @param data  Caller supplied data to be passed to the callback
 *
 * @return  Status code indicating success or failure
 *          - DPS_OK if a link is being tried, the success or failure will be reported in the callback
 *          - DPS_ERR_NO_ROUTE if no new links can be established
 *          - Other error status codes
 */
DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_RegistrationList* regs, DPS_OnRegLinkToComplete cb, void* data);

/**
 * Synchronous version of Registration_LinkTo
 *
 * @param node  The local node to link
 * @param regs  The list of candidate registrations to try to link to
 * @param addr  Set to the address of the linked candidate
 *
 * @return  Status code indicating success or failure
 *          - DPS_OK if a link was successfully established
 *          - DPS_ERR_NO_ROUTE if no new links can be established
 *          - Other error status codes
 */
DPS_Status DPS_Registration_LinkToSyn(DPS_Node* node, DPS_RegistrationList* regs, DPS_NodeAddress* addr);

/** @} */ // end of registration group

/** @} */ // end of services group

#ifdef __cplusplus
}
#endif

#endif
