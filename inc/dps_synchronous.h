#ifndef _DPS_SYNCHRONOUS_H
#define _DPS_SYNCHRONOUS_H

#include <dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Synchronous helper APIs that wrap the asynchronous versions
 */


/**
 * Resolve a host and port and establish a link to a remote node.
 *
 * @param node  The local node to link from
 * @param host  The host name or IP address to link to
 * @param port  The port number
 * @param addr  Returns the resolved address for the remote node
 *
 */
DPS_Status DPS_LinkTo(DPS_Node* node, const char* host, uint16_t port, DPS_NodeAddress* addr);


/**
 * Unlink from a previously linked remote node
 *
 * @param node  The local node to unlink from
 * @param addr  The address of the remote node to unlink
 */
DPS_Status DPS_UnlinkFrom(DPS_Node* node, DPS_NodeAddress* addr);

#ifdef __cplusplus
}
#endif

#endif
