/**
 * @file
 * Network layer macros and functions
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

#ifndef _NETWORK_H
#define _NETWORK_H

#include <stdint.h>
#include <dps/private/dps.h>
#include <dps/private/io_buf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function prototype for handler to be called on receiving data from a remote node
 *
 * @param node      The node that received the data
 * @param rxBuf     The receive buffer
 * @param status    Indicates if the receive was successful or there was a network layer error
 *
 * @return
 * - DPS_OK if the message was correctly parsed
 * - An error code indicating the data received was invalid
 */
typedef DPS_Status (*DPS_OnReceive)(DPS_Node* node, DPS_RxBuffer* rx, DPS_Status status);

/**
 * Prototype for function called when a send completes.
 *
 * @param node     Opaque pointer to the DPS node
 * @param appCtx   Application context pointer that was passed into the send function
 * @param status   Indicates if the send was successful or not
 */
typedef void (*DPS_SendComplete)(DPS_Node* node, void* appCtx, DPS_Status status);

/**
 * Initialize networking
 */
DPS_Status DPS_NetworkInit(DPS_Node* node);

/**
 * Terminate networking freeing any resources that we allocated
 */
void DPS_NetworkTerminate(DPS_Node* node);

/**
 * Start receiving multicast data
 *
 * @param node     Opaque pointer to the DPS node
 * @param cb       Function prototype for handler to be called on receiving data from a remote node
 */
DPS_Status DPS_MCastStart(DPS_Node* node, DPS_OnReceive cb);

/**
 * Stop receiving multicast data
 *
 * @param node     Opaque pointer to the DPS node
 */
void DPS_MCastStop(DPS_Node* node);

/**
 * Multicast data in the node transmit buffer
 *
 * @param node            Opaque pointer to the DPS node
 * @param appCtx          An application context to be passed to the send complete callback
 * @param sendCompleteCB  Function called when the send is complete
 *
 * @return
 * - DPS_OK if send is successful,
 * - DPS_ERR_NO_ROUTE if no interfaces are usable for multicast,
 * - an error otherwise
 */
DPS_Status DPS_MCastSend(DPS_Node* node, void* appCtx, DPS_SendComplete sendCompleteCB);

/**
 * Start listening and receiving unicast data
 *
 * @param node  Opaque pointer to the DPS node
 * @param port  If non-zero the port number to listen on, if zero use an ephemeral port
 * @param cb    Function to call when data is received
 *
 * @return   Returns a pointer to an opaque data structure that holds the state of the netCtx.
 */
DPS_Status DPS_UnicastStart(DPS_Node* node, uint16_t port, DPS_OnReceive cb);

/**
 * Stop listening for data
 *
 * @param netCtx  Pointer to an opaque data structure that holds the network state.
 *                The netCtx will be freed and this pointer will be invalid after this call.
 */
void DPS_UnicastStop(DPS_Node* node);

/**
 * Send data in the tx buffer to a previously specified remote node
 *
 * @param node            Pointer to the DPS node
 * @param txBuf           The transmit buffer
 * @param appCtx          An application context to be passed to the send complete callback
 * @param sendCompleteCB  Function called when the send is complete so the content of the data buffers can be freed.
 *
 * @return DPS_OK if the send is successful, an error otherwise
 */
DPS_Status DPS_UnicastSend(DPS_Node* node, DPS_TxBuffer* txBuf, void* appCtx, DPS_SendComplete sendCompleteCB);

#ifdef __cplusplus
}
#endif

#endif
