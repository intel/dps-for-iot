#ifndef _NETWORK_H
#define _NETWORK_H

#include <stdint.h>
#include <dps_internal.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DPS_MulticastReceiver DPS_MulticastReceiver;

/**
 * Function prototype for handler to be called on receiving data from a remote node
 *
 * @param node  The node that received the data
 * @param data  The raw data 
 * @param len   Length of the raw data
 *
 * @return  If positive the minimum number of bytes still to be read
 *          If negative the excess bytes to be pushed back
 */
typedef ssize_t (*DPS_OnReceive)(DPS_Node* node, const struct sockaddr* addr, const uint8_t* data, size_t len);

/*
 * Start receiving multicast data
 */
DPS_MulticastReceiver* DPS_MulticastStartReceive(DPS_Node* node, DPS_OnReceive cb);

/*
 * Stop receiving multicast data
 */
void DPS_MulticastStopReceive(DPS_MulticastReceiver* receiver);


typedef struct _DPS_MulticastSender DPS_MulticastSender;

/*
 * Setup to enable sending multicast data
 *
 * @param node     Opaque pointer to the DPS node 
 *
 * @return   An opaque pointer to a struct holding the state of the multicast sender.
 */
DPS_MulticastSender* DPS_MulticastStartSend(DPS_Node* node);

/*
 * Free resources used for sending multicast data
 *
 * @param node     Opaque pointer to the DPS node 
 * @param sender   An opaque pointer to a struct holding the state of the multicast sender.
 *                 This will be free after this call and the pointer will no longer be valid.
 */
void DPS_MulticastStopSend(DPS_MulticastSender* sender);

/*
 * Prototype for function called when a send completes 
 *
 * @param node     Opaque pointer to the DPS node 
 * @param addr     Remote address
 * @param bufs     Array holding pointers to the buffers passed in the send API call. The data in these buffers
 *                 can now be freed. 
 * @param          The length of the bufs array
 * @param status   Indicates if the send was successful or not
 */
typedef void (*DPS_NetSendComplete)(DPS_Node* node, struct sockaddr* addr, uv_buf_t* bufs, size_t numBufs, DPS_Status status);

/*
 * Multicast some data immediately
 *
 * @param node     Opaque pointer to the DPS node 
 * @param bufs     Data buffers to send
 * @param numBufs  Number of buffers to send
 */
DPS_Status DPS_MulticastSend(DPS_MulticastSender* sender, uv_buf_t* bufs, size_t numBufs);

/*
 * Opaque data structure for a TCP listener
 */
typedef struct _DPS_NetListener DPS_NetListener;

/*
 * Start listening and receiving data on TCP connections
 *
 * @param node  Opaque pointer to the DPS node 
 * @param port  If non-zero the port number to listen on, if zero use an ephemeral port
 * @param cb    Function to call when data is received
 *
 * @return   Returns a pointer to an opaque data structure that holds the state of the listener.
 */
DPS_NetListener* DPS_NetStartListening(DPS_Node* node, int port, DPS_OnReceive cb);

/*
 * Get the port the listener is listening on
 *
 * @param listener  Pointer to an opaque data structure that holds the state of the listener.
 */
uint16_t DPS_NetGetListenerPort(DPS_NetListener* listener);

/*
 * Stop listening for new TCP connections
 *
 * @param listener  Pointer to an opaque data structure that holds the state of the listener.
 *                  The listener will be freed and this pointer will be invalid after this call.
 */
void DPS_NetStopListening(DPS_NetListener* listener);

/*
 * Connect and send data to a specific destination address
 *
 * @param node            Opaque pointer to the DPS node 
 * @param bufs            Data buffers to send, the data in the buffers must be live until the send completes.
 * @param numBufs         Number of buffers to send
 * @param addr            Destination address
 * @param sendCompleteCB  Function called when the send is completeso the content of the data buffers can be freed.
 */
DPS_Status DPS_NetSend(DPS_Node* node, uv_buf_t* bufs, size_t numBufs, const struct sockaddr* addr, DPS_NetSendComplete sendCompleteCB);

/*
 * Generates text for an address
 *
 * This function uses a static string internally so is not thread-safe
 */
const char* DPS_NetAddrText(const struct sockaddr* addr);

#ifdef __cplusplus
}
#endif

#endif
