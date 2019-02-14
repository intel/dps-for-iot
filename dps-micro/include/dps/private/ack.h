/**
 * @file
 * Send and receive acknowledgement messages
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

#ifndef _ACK_H
#define _ACK_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include <dps/private/node.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decode and process a received acknowledgement
 *
 * @param node    The local node
 * @param from    The address of the sender
 * @param buffer  The encoded acknowledgement
 *
 * @return DPS_OK if decoding and processing is successful, an error otherwise
 */
DPS_Status DPS_DecodeAcknowledgement(DPS_Node* node, DPS_NodeAddress* from, DPS_RxBuffer* buffer);

/**
 * Send an previously serialized acknowledgement
 *
 * Must be called with the node lock held.
 *
 * @param pub      The publication to acknowledge
 * @param data     Optional payload for the acknowledgment
 * @param dataLen  The length of the optional payload
 *
 * @return DPS_OK if sending is successful, an error otherwise
 */
DPS_Status DPS_AckPublication(const DPS_Publication* pub, const uint8_t* data, size_t dataLen);

#ifdef __cplusplus
}
#endif

#endif
