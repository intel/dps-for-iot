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
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/private/network.h>
#include "coap.h"

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define USE_IPV4       0x10
#define USE_IPV6       0x01

#define MAX_INTERFACE_NAME_LEN   64

struct _DPS_MulticastReceiver {
    uint8_t ipVersions;
    uv_udp_t udp6Rx;
    uv_udp_t udp4Rx;
    DPS_Node* node;
    DPS_OnReceive cb;
};

typedef struct {
    uv_udp_t udp;
    uv_udp_send_t req;
    int family;
} TxSocket;

struct _DPS_MulticastSender {
    uint8_t ipVersions;
    TxSocket* udpTx;  /* Array of Tx sockets - one per interface */
    size_t numTx;     /* Number of Tx sockets */
    DPS_Node* node;
};

static int UseInterface(uint8_t ipVersions, uv_interface_address_t* ifn)
{
    if (ifn->is_internal) {
        return 0;
    }
    if (ifn->address.address4.sin_family == AF_INET6) {
        return ipVersions & USE_IPV6;
    } else {
        return ipVersions & USE_IPV4;
    }
}

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    buf->len = (uint32_t)suggestedSize;
    buf->base = malloc(buf->len);
}

static void OnMcastRx(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_MulticastReceiver* receiver = (DPS_MulticastReceiver*)handle->data;
    DPS_NetEndpoint ep;

    DPS_DBGPRINT("OnMcastRx\n");
    if (nread < 0) {
        DPS_ERRPRINT("Read error %s\n", uv_err_name((int)nread));
        uv_close((uv_handle_t*)handle, NULL);
        free(buf->base);
        return;
    }
    if (addr) {
        DPS_DBGPRINT("Received buffer of size %zd from %s\n", nread, DPS_NetAddrText(addr));
    }
    ep.cn = NULL;
    DPS_SetAddress(&ep.addr, addr);
    receiver->cb(receiver->node, &ep, DPS_OK, (uint8_t*)buf->base, nread);
    free(buf->base);
}

static DPS_Status MulticastRxInit(DPS_MulticastReceiver* receiver)
{
    int ret;
    struct sockaddr_storage recv_addr;
    uv_loop_t* uv = DPS_GetLoop(receiver->node);
    uv_interface_address_t* ifsAddrs;
    int numIfs;
    int i;

    DPS_DBGPRINT("MulticastRxInit UDP port %d\n", COAP_UDP_PORT);

    /*
     * Initialize v4 udp multicast listener
     */
    if (receiver->ipVersions & USE_IPV4) {
        ret = uv_udp_init(uv, &receiver->udp4Rx);
        assert(ret == 0);
        ret = uv_ip4_addr("0.0.0.0", COAP_UDP_PORT, (struct sockaddr_in*)&recv_addr);
        ret = uv_udp_bind(&receiver->udp4Rx, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
        if (ret) {
            DPS_ERRPRINT("UDP IPv6 bind failed %s\n", uv_err_name(ret));
            return DPS_ERR_NETWORK;
        }
    }
    /*
     * Initialize v6 udp multicast listener
     */
    if (receiver->ipVersions & USE_IPV6) {
        ret = uv_udp_init(uv, &receiver->udp6Rx);
        if (ret == 0) {
            ret = uv_ip6_addr("::", COAP_UDP_PORT, (struct sockaddr_in6*)&recv_addr);
        }
        if (ret == 0) {
            ret = uv_udp_bind(&receiver->udp6Rx, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
        }
        if (ret) {
            DPS_ERRPRINT("UDP IPv6 bind failed %s\n", uv_err_name(ret));
            return DPS_ERR_NETWORK;
        }
    }
    uv_interface_addresses(&ifsAddrs, &numIfs);
    for (i = 0; i < numIfs; ++i) {
        uv_interface_address_t* ifn = &ifsAddrs[i];
        char name[INET6_ADDRSTRLEN + 1];
        /*
         * Filter out interfaces we are not interested in
         */
        if (!UseInterface(receiver->ipVersions, ifn)) {
            continue;
        }
        if (ifn->address.address4.sin_family == AF_INET6) {
            char ifaddr[INET6_ADDRSTRLEN + + MAX_INTERFACE_NAME_LEN + 2];
            ret = uv_ip6_name((struct sockaddr_in6*)&ifn->address, name, sizeof(name));
            assert(ret == 0);
            name[sizeof(name) - 1] = 0;
            snprintf(ifaddr, sizeof(ifaddr), "%s%%%s", name, ifn->name);
            DPS_DBGPRINT("Joining IPv6 interface %s [%s]\n", ifn->name, ifaddr);
            ret = uv_udp_set_membership(&receiver->udp6Rx, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, ifaddr, UV_JOIN_GROUP);
        } else {
            ret = uv_ip4_name((struct sockaddr_in*)&ifn->address, name, sizeof(name));
            assert(ret == 0);
            DPS_DBGPRINT("Joining IPv4 interface %s [%s]\n", ifn->name, name);
            ret = uv_udp_set_membership(&receiver->udp4Rx, COAP_MCAST_ALL_NODES_LINK_LOCAL_4, name, UV_JOIN_GROUP);
        }
        if (ret) {
            DPS_WARNPRINT("Join group failed %s: %s\n", ifn->name, uv_err_name(ret));
        }
    }
    uv_free_interface_addresses(ifsAddrs, numIfs);
    /*
     * Start listening for data
     */
    if (receiver->ipVersions & USE_IPV4) {
        receiver->udp4Rx.data = receiver;
        ret = uv_udp_recv_start(&receiver->udp4Rx, AllocBuffer, OnMcastRx);
        assert(ret == 0);
    }
    if (receiver->ipVersions & USE_IPV6) {
        receiver->udp6Rx.data = receiver;
        ret = uv_udp_recv_start(&receiver->udp6Rx, AllocBuffer, OnMcastRx);
        assert(ret == 0);
    }
    return DPS_OK;
}

DPS_MulticastReceiver* DPS_MulticastStartReceive(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Status ret;
    DPS_MulticastReceiver* receiver = calloc(1, sizeof(DPS_MulticastReceiver));

    if (!receiver) {
        return NULL;
    }
    receiver->ipVersions = USE_IPV6 | USE_IPV4;
    receiver->cb = cb;
    receiver->node = node;

    ret = MulticastRxInit(receiver);
    if (ret != DPS_OK) {
        free(receiver);
        return NULL;
    }
    return receiver;
}

static void RxCloseCB(uv_handle_t* handle);

static void MulticastStopReceive(DPS_MulticastReceiver* receiver)
{
    if (receiver->ipVersions & USE_IPV4) {
        receiver->ipVersions &= ~USE_IPV4;
        uv_close((uv_handle_t*)&receiver->udp4Rx, RxCloseCB);
    } else if (receiver->ipVersions & USE_IPV6) {
        receiver->ipVersions &= ~USE_IPV6;
        uv_close((uv_handle_t*)&receiver->udp6Rx, RxCloseCB);
    } else {
        free(receiver);
    }
}

static void RxCloseCB(uv_handle_t* handle)
{
    DPS_MulticastReceiver* receiver = (DPS_MulticastReceiver*)handle->data;
    MulticastStopReceive(receiver);
}

void DPS_MulticastStopReceive(DPS_MulticastReceiver* receiver)
{
    MulticastStopReceive(receiver);
}

/*****************************************************
 * Send path
 ****************************************************/

static DPS_Status MulticastTxInit(DPS_MulticastSender* sender)
{
    int ret;
    uv_loop_t* uv = DPS_GetLoop(sender->node);
    uv_interface_address_t* ifsAddrs;
    TxSocket* sock;
    int numIfs;
    int i;

    DPS_DBGPRINT("MulticastTxInit\n");

    uv_interface_addresses(&ifsAddrs, &numIfs);
    /*
     * Count the usable interfaces
     */
    for (i = 0; i < numIfs; ++i) {
        uv_interface_address_t* ifn = &ifsAddrs[i];
        if (UseInterface(sender->ipVersions, ifn)) {
            ++sender->numTx;
        }
    }
    /*
     * Allocate array of sockets, one per interface
     */
    sender->udpTx = sock = calloc(1, sizeof(TxSocket) * sender->numTx);
    /*
     * Bind and set the interface address on each socket
     */
    for (i = 0; i < numIfs; ++i) {
        struct sockaddr_storage addr;
        char ifaddr[INET6_ADDRSTRLEN + MAX_INTERFACE_NAME_LEN + 2];
        uv_interface_address_t* ifn = &ifsAddrs[i];
        if (!UseInterface(sender->ipVersions, ifn)) {
            continue;
        }
        sock->family = ifn->address.address4.sin_family;
        if (sock->family == AF_INET6) {
            ret = uv_ip6_addr("::", 0, (struct sockaddr_in6*)&addr);
        } else {
            ret = uv_ip4_addr("0.0.0.0", 0, (struct sockaddr_in*)&addr);
        }
        if (ret) {
            continue;
        }
        /*
         * Initialize udp Tx socket
         */
        ret = uv_udp_init(uv, &sock->udp);
        assert(ret == 0);
        ret = uv_udp_bind(&sock->udp, (const struct sockaddr *)&addr, 0);
        assert(ret == 0);
        if (sock->family == AF_INET6) {
            char name[INET6_ADDRSTRLEN + 1];
            /*
             * Append interface name to the interface address for IPv6
             */
            ret = uv_ip6_name(&ifn->address.address6, name, sizeof(name));
            if (ret == 0) {
                name[sizeof(name) - 1] = 0;
                snprintf(ifaddr, sizeof(ifaddr), "%s%%%s", name, ifn->name);
            }
        } else {
            /*
             * Just the address for IPV4
             */
            ret = uv_ip4_name(&ifn->address.address4, ifaddr, sizeof(ifaddr));
        }
        if (ret) {
            DPS_ERRPRINT("Failed to get interface name: %s\n", uv_err_name(ret));
            continue;
        }
        DPS_DBGPRINT("Setting interface %s [%s]\n", ifn->name, ifaddr);
        ret = uv_udp_set_multicast_interface(&sock->udp, ifaddr);
        if (ret) {
            DPS_ERRPRINT("Failed to set interface: %s\n", uv_err_name(ret));
            continue;
        }
        /*
         * Store pointer back to the sender struct
         */
        sock->udp.data = sender;
        ++sock;
    }
    uv_free_interface_addresses(ifsAddrs, numIfs);
    return DPS_OK;
}

DPS_MulticastSender* DPS_MulticastStartSend(DPS_Node* node)
{
    DPS_Status ret;
    DPS_MulticastSender* sender = calloc(1, sizeof(DPS_MulticastSender));

    if (!sender) {
        return NULL;
    }
    sender->ipVersions = USE_IPV6 | USE_IPV4;
    sender->node = node;

    ret = MulticastTxInit(sender);
    if (ret != DPS_OK) {
        if (sender->udpTx) {
            free(sender->udpTx);
        }
        free(sender);
        return NULL;
    }
    return sender;
}

static void TxCloseCB(uv_handle_t* handle)
{
    DPS_MulticastSender* sender = (DPS_MulticastSender*)handle->data;
    if (--sender->numTx == 0) {
        free(sender->udpTx);
        free(sender);
    }
}

void DPS_MulticastStopSend(DPS_MulticastSender* sender)
{
    size_t i;
    for (i = 0; i < sender->numTx; ++i) {
        uv_close((uv_handle_t*)&sender->udpTx[i].udp, TxCloseCB);
    }
}

static void MulticastSendComplete(uv_udp_send_t* req, int status)
{
    if (status) {
        DPS_ERRPRINT("uv_udp_send failed: %s\n", uv_err_name(status));
    }
}

DPS_Status DPS_MulticastSend(DPS_MulticastSender* sender, uv_buf_t* bufs, size_t numBufs)
{
    size_t i;
    /*
     * Send on each interface
     */
    for (i = 0; i < sender->numTx; ++i) {
        int ret;
        struct sockaddr_storage addr;
        if (sender->udpTx[i].family == AF_INET6) {
            ret = uv_ip6_addr(COAP_MCAST_ALL_NODES_LINK_LOCAL_6, COAP_UDP_PORT, (struct sockaddr_in6*)&addr);
        } else {
            ret = uv_ip4_addr(COAP_MCAST_ALL_NODES_LINK_LOCAL_4, COAP_UDP_PORT, (struct sockaddr_in*)&addr);
        }
        if (ret) {
            continue;
        }
        /*
         * Synchronous send
         */
        ret = uv_udp_send(&sender->udpTx[i].req, &sender->udpTx[i].udp, bufs, (unsigned int)numBufs, (struct sockaddr*)&addr, MulticastSendComplete);
        if (ret) {
            DPS_ERRPRINT("uv_udp_send to %s failed: %s\n", DPS_NetAddrText((struct sockaddr*)&addr), uv_err_name(ret));
        } else {
#ifndef NDEBUG
            size_t len = 0;
            int j;
            for (j = 0; j < numBufs; ++j) {
                len += bufs[j].len;
            }
            DPS_DBGPRINT("DPS_MulitcastSend total %zu bytes to %s\n", len, DPS_NetAddrText((struct sockaddr*)&addr));
#endif
        }
    }
    return DPS_OK;
}
