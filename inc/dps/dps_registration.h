#ifndef _DPS_REGISTRATION_H
#define _DPS_REGISTRATION_H

#include <dps/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * APIs for interacting with a registration service
 */

const char* DPS_RegistryTopicString;

#define DPS_CANDIDATE_TRYING    1  /** An attempt is being made link to a candidate */
#define DPS_CANDIDATE_FAILED    2  /** An attempt to link to a candidate was attempted but failed */
#define DPS_CANDIDATE_LINKED    4  /** Candidate is currently linked */
#define DPS_CANDIDATE_UNLINKED  8  /** Candidate was linked but is currently not linked */

typedef struct {
    uint8_t flags;
    DPS_NodeAddress addr;
} DPS_Candidate;

/**
 * For returning a list of candidate remote nodes
 */
typedef struct {
    size_t count;
    DPS_Candidate* candidates;
} DPS_CandidateList;

/**
 * Function prototype for callback called when DPS_Registration_Put() completes
 *
 * @param status      DPS_OK if the registration was made
 * @param data        Caller supplied data passed into the DPS_Registration_Put()
 *
 */
typedef void (*DPS_OnRegPutComplete)(DPS_Status status, void* data);

/**
 * Resolve the host and port of a registration service and register a local node with
 * that service.
 *
 * @param node          The local node to register
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param cb            Callback called when the registration completes.
 * @param data          Caller provided data to be passed to the callback function
 *
 */
DPS_Status DPS_Registration_Put(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_OnRegPutComplete cb, void* data);

/**
 * Synchronous version of DPS_RegistrationPut(). This function blocks until the operations is
 * complete.
 *
 * @param node          The local node to register
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 *
 */
DPS_Status DPS_Registration_PutSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString);

/**
 * Function prototype for callback called when DPS_Regisration_Get() completes
 *
 * @param candidates  Struct containing the list of candidate passed in to DPS_Registration_Get()
 * @param status      DPS_OK if candidates were returned, DPS_ERR_TIMEOUT if no candidates were
 *                    received with the response time window.
 * @param data        Caller supplied data passed into the DPS_Registration_Get()
 */
typedef void (*DPS_OnRegGetComplete)(DPS_CandidateList* candidates, DPS_Status status, void* data);

/**
 * Resolve the host and port of a registration service and lookup the addresses
 * registered with that service.
 *
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param list          Candidate list for accumulating the results. The count field must be
 *                      initialized with the maximum number of candidates to be returned. The
 *                      candidate list pointer must remanin valid until the callback is called.
 * @param cb            The callback to call with the result
 * @param data          Called supplied data to be passed to the callback
 *
 */
DPS_Status DPS_Registration_Get(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_CandidateList* list, DPS_OnRegGetComplete cb, void* data);

/**
 * A synchronous version of DPS_RegistrationGet() this function blocks until the candidate list has
 * been populated or the request times out.
 *
 * @param host          The host name or IP address to register with
 * @param port          The port number
 * @param tenantString  Topic string indentifying the tenant
 * @param list          Candidate list for accumulating the results. The count field must be
 *                      initialized with the maximum number of candidates to be returned.
 *
 */
DPS_Status DPS_Registration_GetSyn(DPS_Node* node, const char* host, uint16_t port, const char* tenantString, DPS_CandidateList* list);

/**
 * Function prototype for callback called when DPS_Registration_LinkTo() completes
 *
 * @param list     The list of candidate addressess passed in to DPS_Registration_LinkTo().
 * @param addr     The address if the remote if status == DPS_OK
 * @param status   - DPS_OK if a link was sucessfully established
 *                 - DPS_ERR_NO_ROUTE if a link could not be established
 * @param data     Caller supplied data passed into the DPS_Registration_LinkTo()
 *
 */
typedef void (*DPS_OnRegLinkToComplete)(DPS_Node* node, DPS_CandidateList* list, DPS_NodeAddress* addr, DPS_Status status, void* data);

/**
 * Randomly select a remote candidate to link to. 
 *
 * @param node        The local node to link 
 * @param candidates  The list of candidate to link to
 * @param cb          The callback to call with the result
 * @param data        Called supplied data to be passed to the callback
 *
 * @return  DPS_OK if a link is being tried
 *          DPS_ERR_NO_ROUTE if no new links can be established
 */
DPS_Status DPS_Registration_LinkTo(DPS_Node* node, DPS_CandidateList* candidates, DPS_OnRegLinkToComplete cb, void* data);

/**
 * Synchronous version of Registration_LinkTo
 *
 * @param node        The local node to link 
 * @param candidates  The list of candidate to link to
 * @param addr        Returns the address of the linked candidate
 *
 */
DPS_Status DPS_Registration_LinkToSyn(DPS_Node* node, DPS_CandidateList* candidates, DPS_NodeAddress* addr);

#ifdef __cplusplus
}
#endif

#endif
