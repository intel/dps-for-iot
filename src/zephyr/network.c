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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr.h>

#include <misc/byteorder.h>
#include <misc/util.h>
#include <net/ethernet.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_ip.h>
#include <net/udp.h>

#include <dps/dps.h>
#include <dps/err.h>
#include <dps/dbg.h>
#include <dps/private/node.h>
#include <dps/private/coap.h>
#include <dps/private/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define RX_BUFFER_SIZE 2048

#define IPV4  0
#define IPV6  1

struct _DPS_Network {
    struct net_context* context4;       /* Zephyr IPv4 network context */
    struct net_context* context6;       /* Zephyr IPv6 network context */
    uint8_t rxBuffer[RX_BUFFER_SIZE]; 
    size_t txLen;
    DPS_OnReceive mcastRecvCB;
    DPS_OnReceive recvCB;
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
};

static DPS_Network netContext;

DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;
    int ret;

    DPS_DBGTRACE();

    /* Initialize the Ethernet driver on the default interface */
    ethernet_init(net_if_get_default());

    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;

    /* Get the Zephyr IPv6 network context */
    ret = net_context_get(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &netContext.context6);
	if (ret) {
		DPS_DBGPRINT("Could not get ipV6 UDP context\n");
		status = DPS_ERR_NETWORK;
    }
    return status;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
}

static DPS_Status BindSock(int family, DPS_Network* net, int port)
{
    DPS_Status status = DPS_OK;
    int ret;

    if (family == AF_INET) {
        struct sockaddr_in addrAny4;
        memset(&addrAny4, 0, sizeof(addrAny4));
        addrAny4.sin_family = AF_INET;
        addrAny4.sin_addr.s_addr = INADDR_ANY;
        addrAny4.sin_port = htons(port);
        ret = net_context_bind(net->context4, (struct sockaddr*)&addrAny4, sizeof(addrAny4));
    } else {
        struct sockaddr_in6 addrAny6;
        memset(&addrAny6, 0, sizeof(addrAny6));
        addrAny6.sin6_port = htons(port);
        addrAny6.sin6_family = AF_INET6;
        addrAny6.sin6_addr = in6addr_any;
        ret = net_context_bind(net->context6, (struct sockaddr*)&addrAny6, sizeof(addrAny6));
    }
    if (ret) {
        DPS_DBGPRINT("bind() %s failed. 0x%x\n", family == AF_INET ? "IPv4" : "IPv6", ret);
        status = DPS_ERR_NETWORK;
    }
    return status;
}

/* Local IPv6 address - TODO should be randomly assiged or a configuration parameter */
#define LOCAL_ADDR_6   "2001:db8::1"

static DPS_Status JoinMCastGroup()
{
    int ret;
	struct in6_addr addr6;
    struct in6_addr mcast6;
	struct net_if_addr* ifaddr;
    struct net_if_mcast_addr* mcast;
	struct net_if* iface;

    DPS_DBGTRACE();

	iface = net_if_get_default();
	if (!iface) {
		DPS_DBGPRINT("Could not get the default interface\n");
		return DPS_ERR_NETWORK;
	}

    /* Need to set a unicast address on the interface */
    ret = net_addr_pton(AF_INET6, LOCAL_ADDR_6, &addr6);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 address\n");
		return DPS_ERR_NETWORK;
    }
	ifaddr = net_if_ipv6_addr_add(iface, &addr6, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		DPS_DBGPRINT("Could not add unicast address to interface");
		return DPS_ERR_NETWORK;
	}

	ifaddr->addr_state = NET_ADDR_PREFERRED;

    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &mcast6);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 multicast address\n");
		return DPS_ERR_NETWORK;
    }
	mcast = net_if_ipv6_maddr_add(iface, &mcast6);
	if (!mcast) {
		DPS_DBGPRINT("Could not add multicast address to interface\n");
		return DPS_ERR_NETWORK;
	}

	return DPS_OK;
}

static void OnData(struct net_context* context, struct net_pkt* pkt, int status, void* userData)
{
    DPS_Node* node = (DPS_Node*)userData;
    DPS_Network* net = node->network;
    unsigned int hdrLen;
    unsigned int rcvLen;
    DPS_RxBuffer rxBuf;

    /* 
	 * Skip the packet header (fits in the first fragment) - TODO we eventually need to extract the source address
	 */
	hdrLen = net_pkt_appdata(pkt) - pkt->frags->data;

	rcvLen = net_pkt_appdatalen(pkt);
	if (rcvLen > RX_BUFFER_SIZE) {
		DPS_DBGPRINT("Packet to large for receive buffer\n");
        return;
	}
	net_frag_linearize(net->rxBuffer, rcvLen, pkt, hdrLen, rcvLen);
    /* We are done with the packet so unref it so it can be freed */
    net_pkt_unref(pkt);

    DPS_RxBufferInit(&rxBuf, net->rxBuffer, rcvLen);
    net->mcastRecvCB(node, &rxBuf, DPS_OK);
}

DPS_Status DPS_MCastStart(DPS_Node* node, DPS_OnReceive cb)
{
    int ret;
    DPS_Status status;
    DPS_Network* network = node->network;

    DPS_DBGTRACE();

    status = JoinMCastGroup();
    if (status != DPS_OK) {
        goto Exit;
    }
    status = BindSock(AF_INET6, network, COAP_UDP_PORT);
    if (status != DPS_OK) {
        goto Exit;
    }
    network->mcastRecvCB = cb;

	ret = net_context_recv(network->context6, OnData, K_NO_WAIT, node);
	if (ret) {
		DPS_DBGPRINT("Could not register callback\n");
		status = DPS_ERR_NETWORK;
        goto Exit;
	}

Exit:
    return status;
}

DPS_Status DPS_MCastSend(DPS_Node* node, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Network* net = node->network;
    int ret;
    struct sockaddr_in6 addr6;
    unsigned int len = (unsigned int)(node->txLen + node->txHdrLen);
    uint8_t* buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;
    struct net_pkt* pkt;

    memset(&addr6, 0, sizeof(addr6));
    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &addr6.sin6_addr);
    if (ret) {
        return DPS_ERR_NETWORK;
    }
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(COAP_UDP_PORT);

    pkt = net_pkt_get_tx(net->context6, K_FOREVER);
    if (!pkt) {
        return DPS_ERR_NETWORK;
    }
    len = net_pkt_append(pkt, len, buf, K_FOREVER);
    if (!len) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
    /* TODO - register completetion callback */
    ret = net_context_sendto(pkt, (struct sockaddr*)&addr6, sizeof(addr6), NULL, K_FOREVER, NULL, node);
    if (ret < 0) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
	return DPS_OK;
}
