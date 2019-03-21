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
#include <dps/private/malloc.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
  * Abstract type for network state information
  */
typedef struct _DPS_Network DPS_Network;

/**
  * Abstract type for DTLS state information
  */
typedef struct _DPS_DTLS DPS_DTLS;
    
/**
  * Abstract type for a DPS node address
  */
typedef struct _DPS_NodeAddress DPS_NodeAddress;

/**
  * Set the port on a node address
  */
void DPS_NodeAddressSetPort(DPS_NodeAddress* addr, uint16_t port);

/**
  * Copy a node address
  */
void DPS_CopyNodeAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src);

/**
  * Compare to addresses
  */
int DPS_SameNodeAddress(const DPS_NodeAddress* addr1, const DPS_NodeAddress* addr2);

/**
  * Returns text string for a specified node address.
  */
const char* DPS_AddrToText(DPS_NodeAddress* addr);

/**
  * Allocate a node address from the requested pool. Call DPS_Free() to free the memory
  */
DPS_NodeAddress* DPS_AllocNodeAddress(DPS_AllocPool pool);

/**
 * Function prototype for handler to be called on receiving data from a remote node
 *
 * @param node      The node that received the data
 * @param from      Address of the node that sent the data
 * @param mcast     Non-zero if the packet was a multicast packet
 * @param rxBuf     The receive buffer
 * @param status    Indicates if the receive was successful or there was a network layer error
 *
 * @return
 * - DPS_OK if the message was correctly parsed
 * - An error code indicating the data received was invalid
 */
typedef DPS_Status (*DPS_OnReceive)(DPS_Node* node, DPS_NodeAddress* from, int mcast, DPS_RxBuffer* rx, DPS_Status status);

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
DPS_Status DPS_NetworkStart(DPS_Node* node, DPS_OnReceive cb);

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
 * Unicast the data in the node transmit buffer
 *
 * @param node            Pointer to the DPS node
 * @param dest            Destination address
 * @param appCtx          An application context to be passed to the send complete callback
 * @param sendCompleteCB  Function called when the send is complete so the content of the data buffers can be freed.
 *
 * @return DPS_OK if the send is successful, an error otherwise
 */
DPS_Status DPS_UnicastSend(DPS_Node* node, DPS_NodeAddress* dest, void* appCtx, DPS_SendComplete sendCompleteCB);

/**
  * Write data synchronously. This is API is called during the DTLS handshake.
  *
  * @param node       Pointer to the DPS node
  * @param dest       Destination address
  * @param data       The data to write
  * @param len        Length of the data to write
  */
DPS_Status DPS_UnicastWrite(DPS_Node* node, DPS_NodeAddress* dest, void* data, size_t len);

/**
  * Write data asynchronously.
  * @param node       Pointer to the DPS node
  * @param dest       Destination address
  * @param data       The data to write
  * @param len        Length of the data to write
  */
DPS_Status DPS_UnicastWriteAsync(DPS_Node* node, DPS_NodeAddress* dest, void* data, size_t len);

/**
  * Read data synchronously. This is API is called during the DTLS handshake.
  *
  * @param node       Pointer to the DPS node
  * @param data       Returns pointer to received data
  * @param len        Returns length of the data received
  * @param timeout    The timeout in milliseconds
  */
DPS_Status DPS_UnicastRead(DPS_Node* node, void** data, size_t* len, int timeout);

/**
  * Get pointer to the DTLS state
  *
  * @param net  Pointer to abstract network state structure
  *
  * @return  Pointer to abstract DTLS state structure
  */
DPS_DTLS* DPS_GetDTLS(DPS_Network* net);

/**
  * Return TRUE if there is a unicast write pending
  */
int DPS_UnicastWritePending(DPS_Network* net);

/**
  * Disable DTLS - this should be called before any DTLS connections are established
  */
void DPS_DisableDTLS(DPS_Node* node);

#ifdef __cplusplus
}
#endif

#endif
