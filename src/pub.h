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

#ifndef _PUB_H
#define _PUB_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include "node.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUB_FLAG_PUBLISH   (0x01) /* The publication should be published */
#define PUB_FLAG_LOCAL     (0x02) /* The publication is local to this node */
#define PUB_FLAG_RETAINED  (0x04) /* The publication had a non-zero TTL */
#define PUB_FLAG_EXPIRED   (0x10) /* The publication had a negative TTL */
#define PUB_FLAG_WAS_FREED (0x20) /* The publication has been freed but has a non-zero ref count */
#define PUB_FLAG_IS_COPY   (0x80) /* This publication is a copy and can only be used for acknowledgements */

/*
 * Notes on the use of the DPS_Publication fields:
 *
 * The pubId identifies a publication that replaces an earlier retained instance of the same publication.
 *
 * The ttl starts when a publication is first published. It may expire before the publication is ever sent.
 * If a publication received by a subscriber has a non-zero ttl is will be retained for later publication
 * until the ttl expires or it is explicitly expired.
 */
typedef struct _DPS_Publication {
    void* userData;
    uint8_t flags;                  /* Internal state flags */
    uint8_t checkToSend;            /* TRUE if this publication should be checked to send */
    uint8_t ackRequested;           /* TRUE if an ack was requested by the publisher */
    uint32_t refCount;              /* Ref count to prevent publication from being free while a send is in progress */
    uint32_t sequenceNum;           /* Sequence number for this publication */
    uint64_t expires;               /* Time (in milliseconds) that this publication expires */
    DPS_AcknowledgementHandler handler;
    DPS_UUID pubId;                 /* Publication identifier */
    DPS_NodeAddress sender;         /* for retained messages - the sender address */
    DPS_BitVector* bf;              /* The Bloom filter bit vector for the topics for this publication */
    DPS_Node* node;                 /* Node for this publication */

    char** topics;                  /* Publication topics - pointers into topicsBuf */
    size_t numTopics;               /* Number of publication topics */
    DPS_TxBuffer topicsBuf;         /* Pre-serialized topic strings */
    DPS_TxBuffer bfBuf;             /* Pre-serialized bloom filter */
    DPS_TxBuffer body;              /* Authenticated body fields */
    DPS_TxBuffer payload;           /* Encrypted body fields */
    DPS_Publication* next;
} DPS_Publication;

#define PUB_TTL(node, pub)  (int16_t)((pub->expires + 999 - uv_now((node)->loop)) / 1000)

/*
 * Run checks of one or more publications against the current subscriptions
 */
void DPS_UpdatePubs(DPS_Node* node, DPS_Publication* pub);

DPS_Status DPS_DecodePublication(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer, int multicast);

DPS_Status DPS_SendPublication(DPS_Node* node, DPS_Publication* pub, DPS_BitVector* bf, RemoteNode* remote);

void DPS_ExpirePub(DPS_Node* node, DPS_Publication* pub);

void DPS_FreePublications(DPS_Node* node);

void DPS_PublicationIncRef(DPS_Publication* pub);

void DPS_PublicationDecRef(DPS_Publication* pub);

#ifndef NDEBUG
void DPS_DumpPubs(DPS_Node* node);
#else
#define DPS_DumpPubs(node)
#endif

#ifdef __cplusplus
}
#endif

#endif
