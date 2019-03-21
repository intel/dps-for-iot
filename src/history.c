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

#include <assert.h>
#include <safe_lib.h>
#include <stdlib.h>
#include <string.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include <dps/uuid.h>
#include "history.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define HISTORY_THRESHOLD   10

/*
 * How long to keep publication history (in nanoseconds)
 */
#define PUB_HISTORY_LIFETIME   DPS_SECS_TO_MS(10)

static DPS_PubHistory* Find(const DPS_History* history, const DPS_UUID* pubId)
{
    DPS_PubHistory* curr = history->root;
    while (curr) {
        int cmp = DPS_UUIDCompare(pubId, &curr->id);
        if (cmp == 0) {
            break;
        }
        if (cmp < 0) {
            curr = curr->left;
        } else {
            curr = curr->right;
        }
    }
    return curr;
}

static void DumpHistory(DPS_PubHistory* ph, int indent, const char* tag)
{
    static const char spaces[] = "                                                          ";
    if (ph) {
        DPS_PRINT("%.*s%s%s\n", indent, spaces, tag, DPS_UUIDToString(&ph->id));
        DumpHistory(ph->left, indent + 2, "L->");
        DumpHistory(ph->right, indent + 2, "R->");
        if (indent) {
            assert(ph == ph->parent->left || ph == ph->parent->right);
        }
    }
}

void DPS_DumpHistory(DPS_History* history)
{
    DumpHistory(history->root, 0, "");
}

/*
 * Adds a new node or returns an existing node
 *
 * UUIDs are random so statistically we expect the tree will be pretty balanced
 */
static DPS_PubHistory* Insert(DPS_History* history, DPS_PubHistory* add)
{
    DPS_PubHistory* curr = history->root;
    DPS_PubHistory* parent = NULL;
    int cmp;

    while (curr) {
        cmp = DPS_UUIDCompare(&add->id, &curr->id);
        if (cmp == 0) {
            break;
        }
        parent = curr;
        if (cmp < 0) {
            curr = curr->left;
        } else {
            curr = curr->right;
        }
    }
    if (curr) {
        return curr;
    }
    if (parent) {
        if (cmp < 0) {
            parent->left = add;
        } else {
            parent->right = add;
        }
        add->parent = parent;
    } else {
        history->root = add;
    }
    return add;
}

static void Remove(DPS_History* history, DPS_PubHistory* ph)
{
    DPS_PubHistory* repl;

    if (ph->left && ph->right) {
        /*
         * Get element that will replace ph in the tree
         *
         * LSB of the UUID does not correlate with the location in the tree
         * so it effectively become a random selection to go left or right
         */
        if (ph->id.val[15] & 1) {
            repl = ph->left;
            while (repl->right) {
                repl = repl->right;
            }
        } else {
            repl = ph->right;
            while (repl->left) {
                repl = repl->left;
            }
        }
        /*
         * Remove the replacement element from the tree
         */
        Remove(history, repl);
        repl->left = ph->left;
        repl->right = ph->right;
        if (repl->left) {
            repl->left->parent = repl;
        }
        if (repl->right) {
            repl->right->parent = repl;
        }
    } else {
        repl = ph->left ? ph->left : ph->right;
    }
    /*
     * Fix up parent pointers
     */
    if (repl) {
        repl->parent = ph->parent;
    }
    if (ph->parent) {
        if (ph->parent->left == ph) {
            ph->parent->left = repl;
        } else {
            ph->parent->right = repl;
        }
    } else {
        history->root = repl;
    }
}

/*
 * Link in according to expiration
 */
static void LinkPub(DPS_History* history, DPS_PubHistory* ph)
{
    assert(!ph->next && !ph->prev);

    if (history->count == 0) {
        assert(!history->latest);
        history->soonest = history->latest = ph;
        history->count = 1;
        return;
    }
    /*
     * Quick check in case this is the soonest
     */
    if (ph->expiration <= history->soonest->expiration) {
        ph->next = history->soonest;
        history->soonest->prev = ph;
        history->soonest = ph;
    } else {
        DPS_PubHistory* h = history->latest;
        /*
         * Work back from latest
         */
        while (ph->expiration < h->expiration) {
            h = h->prev;
        }
        ph->prev = h;
        ph->next = h->next;
        if (h->next) {
            h->next->prev = ph;
        }
        h->next = ph;
        if (h == history->latest) {
            history->latest = ph;
        }
    }
    ++history->count;
}

static DPS_PubHistory* UnlinkPub(DPS_History* history, DPS_PubHistory* ph)
{
    if (ph->prev) {
        ph->prev->next = ph->next;
    } else {
        assert(ph == history->soonest);
        history->soonest = ph->next;
    }
    if (ph->next) {
        ph->next->prev = ph->prev;
    } else {
        assert(ph == history->latest);
        history->latest = ph->prev;
    }
    ph->next = NULL;
    ph->prev = NULL;
    --history->count;
    return ph;
}

static void FreePubHistory(DPS_PubHistory* ph)
{
    DPS_NodeAddressList* addr;
    DPS_NodeAddressList* nextAddr;
    for (addr = ph->addrs; addr; addr = nextAddr) {
        nextAddr = addr->next;
        free(addr);
    }
    free(ph);
}

DPS_Status DPS_DeletePubHistory(DPS_History* history, DPS_UUID* pubId)
{
    DPS_PubHistory* ph;

    DPS_DBGTRACE();

    ph = Find(history, pubId);
    if (!ph) {
        return DPS_ERR_MISSING;
    }
    assert(memcmp(&ph->id, pubId, sizeof(DPS_UUID)) == 0);
    UnlinkPub(history, ph);
    Remove(history, ph);
    FreePubHistory(ph);
    return DPS_OK;
}

void DPS_FreshenHistory(DPS_History* history)
{
    DPS_DBGTRACE();

    uv_mutex_lock(&history->lock);
    if (history->count > HISTORY_THRESHOLD) {
        uint64_t now;

        uv_update_time(history->loop);
        now = uv_now(history->loop);
        while (history->soonest) {
            DPS_PubHistory* ph = history->soonest;
            assert(ph->prev == NULL);
            /*
             * Delete expired history records
             */
            if (now >= ph->expiration) {
                UnlinkPub(history, ph);
                Remove(history, ph);
                FreePubHistory(ph);
            } else {
                break;
            }
        }
    }
    uv_mutex_unlock(&history->lock);
}

DPS_Status DPS_UpdatePubHistory(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum,
                                uint8_t ackRequested, uint16_t ttl, DPS_NodeAddress* addr)
{
    uint64_t now = uv_now(history->loop);
    DPS_PubHistory* phNew = calloc(1, sizeof(DPS_PubHistory));
    DPS_PubHistory* ph;

    DPS_DBGTRACE();

    if (!phNew) {
        return DPS_ERR_RESOURCES;
    }
    phNew->id = *pubId;

    uv_mutex_lock(&history->lock);
    ph = Insert(history, phNew);
    if (ph != phNew) {
        /*
         * Updates existing history
         */
        FreePubHistory(phNew);
        UnlinkPub(history, ph);
    }
    ph->sn = sequenceNum;
    ph->ackRequested = ackRequested;
    /*
     * The address is not set in publications being sent from the local node
     */
    if (addr->type) {
        DPS_NodeAddressList **phAddr;
        for (phAddr = &ph->addrs; (*phAddr); phAddr = &(*phAddr)->next) {
            if (DPS_SameAddr(&(*phAddr)->addr, addr)) {
                break;
            }
        }
        if (!(*phAddr)) {
            (*phAddr) = calloc(1, sizeof(DPS_NodeAddressList));
            if ((*phAddr)) {
                (*phAddr)->sn = sequenceNum;
                (*phAddr)->addr = *addr;
                DPS_DBGPRINT("Added %s to pub %s\n", DPS_NodeAddrToString(&(*phAddr)->addr),
                             DPS_UUIDToString(pubId));
            }
        }
    }
    ph->expiration = now + DPS_SECS_TO_MS(ttl) + PUB_HISTORY_LIFETIME;
    LinkPub(history, ph);
    uv_mutex_unlock(&history->lock);
    return DPS_OK;
}

int DPS_PublicationIsStale(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum)
{
    int stale = DPS_FALSE;
    DPS_PubHistory* ph;

    DPS_DBGTRACE();

    uv_mutex_lock(&history->lock);
    ph = Find(history, pubId);
    if (ph && (sequenceNum <= ph->sn)) {
        stale = DPS_TRUE;
    }
    uv_mutex_unlock(&history->lock);
    return stale;
}

void DPS_HistoryFree(DPS_History* history)
{
    DPS_PubHistory* ph;

    DPS_DBGTRACE();

    ph = history->soonest;
    while (ph) {
        DPS_PubHistory* next = ph->next;
        FreePubHistory(ph);
        ph = next;
    }
    history->latest = NULL;
    history->soonest = NULL;
    history->count = 0;
}

DPS_Status DPS_LookupPublisherForAck(DPS_History* history, const DPS_UUID* pubId, uint32_t* sequenceNum, DPS_NodeAddress** addr)
{
    DPS_Status ret;
    DPS_PubHistory* ph;

    DPS_DBGTRACE();

    uv_mutex_lock(&history->lock);
    ph = Find(history, pubId);
    if (ph && ph->ackRequested && ph->addrs) {
        *sequenceNum = ph->sn;
        *addr = &ph->addrs->addr;
        ret = DPS_OK;
    } else {
        *sequenceNum = 0;
        *addr = NULL;
        ret = DPS_ERR_MISSING;
    }
    uv_mutex_unlock(&history->lock);
    return ret;
}

int DPS_PublicationReceivedFrom(DPS_History* history, DPS_UUID* pubId, uint32_t sequenceNum, DPS_NodeAddress* source, DPS_NodeAddress* destination)
{
    DPS_PubHistory* ph;
    int ret;

    DPS_DBGTRACEA("history=%p,pubId=%s,sequenceNum=%u,source=%s\n", history, DPS_UUIDToString(pubId), sequenceNum, DPS_NodeAddrToString(source));
    DPS_DBGTRACEA("destination=%s\n", DPS_NodeAddrToString(destination));

    if (DPS_SameAddr(source, destination)) {
        return DPS_TRUE;
    }

    ret = DPS_FALSE;
    uv_mutex_lock(&history->lock);
    ph = Find(history, pubId);
    if (ph) {
        DPS_NodeAddressList *phAddr;
        for (phAddr = ph->addrs; phAddr; phAddr = phAddr->next) {
            if ((sequenceNum <= phAddr->sn) && DPS_SameAddr(&phAddr->addr, destination)) {
                ret = DPS_TRUE;
                break;
            }
        }
    }
    uv_mutex_unlock(&history->lock);
    return ret;
}
