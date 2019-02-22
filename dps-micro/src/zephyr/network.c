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

struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
};

struct _DPS_Network {
    struct net_context* ucast4;       /* IPv4 unicast network context */
    struct net_context* mcast4;       /* IPv4 multicast network context */
    struct net_context* ucast6;       /* IPv6 unicast network context */
    struct net_context* mcast6;       /* IPv6 multicast network context */
    uint8_t rxBuffer[RX_BUFFER_SIZE];
    size_t txLen;
    DPS_OnReceive recvCB;
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
};

static DPS_Network netContext;

void DPS_NodeAddressSetPort(DPS_NodeAddress* addr, uint16_t port)
{
    port = htons(port);
    if (addr->inaddr.ss_family == AF_INET6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr->inaddr;
        sa6->sin6_port = port;
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr->inaddr;
        sa4->sin_port = port;
    }
}

DPS_NodeAddress* DPS_AllocNodeAddress(DPS_AllocPool pool)
{
    return DPS_Calloc(sizeof(DPS_NodeAddress), pool);
}

void DPS_CopyNodeAddress(DPS_NodeAddress* dest, const DPS_NodeAddress* src)
{
    memcpy(dest, src, sizeof(DPS_NodeAddress));
}

static const uint8_t IP4as6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

int DPS_SameNodeAddress(const DPS_NodeAddress* addr1, const DPS_NodeAddress* addr2)
{
    const struct sockaddr* a = (const struct sockaddr*)&addr1->inaddr;
    const struct sockaddr* b = (const struct sockaddr*)&addr2->inaddr;
    struct sockaddr_in6 tmp;

    if (a->sa_family != b->sa_family) {
        uint32_t ip;
        tmp.sin6_family = AF_INET6;
        if (a->sa_family == AF_INET6) {
            const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
            tmp.sin6_port = ipb->sin_port;
            ip = ipb->sin_addr.s_addr;
        } else {
            const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
            tmp.sin6_port = ipa->sin_port;
            ip = ipa->sin_addr.s_addr;
        }
        memcpy(&tmp.sin6_addr, IP4as6, 12);
        memcpy((uint8_t*)&tmp.sin6_addr + 12, &ip, 4);
        if (a->sa_family == AF_INET6) {
            b = (const struct sockaddr*)&tmp;
        } else {
            a = (const struct sockaddr*)&tmp;
        }
    }
    if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6) {
        const struct sockaddr_in6* ip6a = (const struct sockaddr_in6*)a;
        const struct sockaddr_in6* ip6b = (const struct sockaddr_in6*)b;
        return (ip6a->sin6_port == ip6b->sin6_port) && (memcmp(&ip6a->sin6_addr, &ip6b->sin6_addr, 16) == 0);
    } else if (a->sa_family == AF_INET && b->sa_family == AF_INET) {
        const struct sockaddr_in* ipa = (const struct sockaddr_in*)a;
        const struct sockaddr_in* ipb = (const struct sockaddr_in*)b;
        return (ipa->sin_port == ipb->sin_port) && (ipa->sin_addr.s_addr == ipb->sin_addr.s_addr);
    } else {
        return DPS_FALSE;
    }
}

DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;
    int ret;

    DPS_DBGTRACE();

    /* Initialize the Ethernet driver on the default interface */
    ethernet_init(net_if_get_default());

    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;

    /* Get the Zephyr IPv6 network contexts */
    ret = net_context_get(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &netContext.mcast6);
	if (ret) {
		DPS_DBGPRINT("Could not get ipV6 multicast context\n");
		status = DPS_ERR_NETWORK;
    }
    ret = net_context_get(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &netContext.ucast6);
	if (ret) {
		DPS_DBGPRINT("Could not get ipV6 unicast context\n");
		status = DPS_ERR_NETWORK;
    }
    return status;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
}

/* Local address - TODO should be randomly assiged or a configuration parameter */
#define LOCAL_ADDR_6   "2001:db8::1"
#define LOCAL_ADDR_4   "169.254.78.133"

static DPS_Status BindSock(int family, DPS_Network* net, int port)
{
    DPS_Status status = DPS_OK;
    int ret;

    DPS_DBGTRACE();
    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        net_addr_pton(AF_INET, LOCAL_ADDR_4, &addr.sin_addr);
        addr.sin_port = htons(port);
        ret = net_context_bind(net->ucast4, (struct sockaddr*)&addr, sizeof(addr));
    } else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        net_addr_pton(AF_INET6, LOCAL_ADDR_6, &addr.sin6_addr);
        addr.sin6_port = htons(port);
        ret = net_context_bind(net->ucast6, (struct sockaddr*)&addr, sizeof(addr));
    }
    if (ret) {
        DPS_DBGPRINT("bind() %s failed. 0x%x\n", family == AF_INET ? "IPv4" : "IPv6", ret);
        status = DPS_ERR_NETWORK;
    }
    return status;
}

static DPS_Status JoinMCastGroup(DPS_Network* net)
{
    int ret;
	struct in6_addr addr6;
    struct sockaddr_in6 mcast6;
	struct net_if_addr* ifaddr;
    struct net_if_mcast_addr* mcast;
	struct net_if* iface;

    DPS_DBGTRACE();

    ret = net_addr_pton(AF_INET6, LOCAL_ADDR_6, &addr6);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 address\n");
		return DPS_ERR_NETWORK;
    }
    memset(&mcast6, 0, sizeof(mcast6));
    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &mcast6.sin6_addr);
    if (ret) {
		DPS_DBGPRINT("Invalid IPv6 multicast address\n");
		return DPS_ERR_NETWORK;
    }

	iface = net_if_get_default();
	if (!iface) {
		DPS_DBGPRINT("Could not get the default interface\n");
		return DPS_ERR_NETWORK;
	}

    /* Need to set a unicast address on the interface */
	ifaddr = net_if_ipv6_addr_add(iface, &addr6, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		DPS_DBGPRINT("Could not add unicast address to interface\n");
		return DPS_ERR_NETWORK;
	}
	ifaddr->addr_state = NET_ADDR_PREFERRED;
    /* Now we can add the multicast address */
	mcast = net_if_ipv6_maddr_add(iface, &mcast6.sin6_addr);
	if (!mcast) {
		DPS_DBGPRINT("Could not add multicast address to interface\n");
		return DPS_ERR_NETWORK;
	}
    /* Bind the multicast address and port */
    mcast6.sin6_family = AF_INET6;
    mcast6.sin6_port = htons(COAP_UDP_PORT);
    ret = net_context_bind(net->mcast6, (struct sockaddr*)&mcast6, sizeof(mcast6));
    if (ret) {
		DPS_DBGPRINT("Unable to bind IPv6 multicast address %d\n", ret);
		return DPS_ERR_NETWORK;
    }
	return DPS_OK;
}

static void OnData(struct net_context* context,
                   struct net_pkt* pkt,
                   union net_ip_header *ip_hdr,
				   union net_proto_header *proto_hdr,
                   int status,
                   void* userData)
{
    DPS_Node* node = (DPS_Node*)userData;
    DPS_Network* net;
    unsigned int hdrLen;
    unsigned int rcvLen;
    DPS_RxBuffer rxBuf;
    DPS_NodeAddress from;
    uint16_t port;

    DPS_DBGTRACE();

    if (!node) {
		DPS_ERRPRINT("Expected a valid node pointer\n");
    }
    net = node->network;
    /*
	 * Skip the packet header (fits in the first fragment)
	 */
	hdrLen = net_pkt_appdata(pkt) - pkt->frags->data;

	rcvLen = net_pkt_appdatalen(pkt);
	if (rcvLen > RX_BUFFER_SIZE) {
		DPS_ERRPRINT("Packet too large for receive buffer\n");
        return;
	}
    port = proto_hdr->udp->dst_port;
	net_buf_linearize(net->rxBuffer, rcvLen, pkt->buffer, hdrLen, rcvLen);
    /* We are done with the packet so unref it so it can be freed */
    net_pkt_unref(pkt);
    /* Extract the source address and port from the headers */
    memset(&from, 0, sizeof(from));
    if (net_pkt_family(pkt) == AF_INET6) {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&from.inaddr;
        memcpy(&sa6->sin6_addr, &ip_hdr->ipv6->src, sizeof(struct in6_addr));
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = port;
    } else {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&from.inaddr;
        memcpy(&sa4->sin_addr, &ip_hdr->ipv4->src, sizeof(struct in_addr));
        sa4->sin_family = AF_INET;
        sa4->sin_port = port;
    }
    DPS_DBGPRINT("Received %d bytes on port %d\n", rcvLen, ntohs(port));
    DPS_RxBufferInit(&rxBuf, net->rxBuffer, rcvLen);
    net->recvCB(node, &from, context == net->mcast6 || context == net->mcast4, &rxBuf, DPS_OK);
}

/* TODO - currently there is no Zephyr API to get the port number */
static uint16_t GetPort(struct net_context* context)
{
    uint16_t port;
    if (context->local.family == AF_INET6) {
        const struct sockaddr_in6_ptr* addr = net_sin6_ptr(&context->local);
        port = addr->sin6_port;
    } else {
        const struct sockaddr_in_ptr* addr = net_sin_ptr(&context->local);
        port = addr->sin_port;
    }
    return ntohs(port);
}

DPS_Status DPS_NetworkStart(DPS_Node* node, DPS_OnReceive cb)
{
    int ret;
    DPS_Status status;
    DPS_Network* network = node->network;

    DPS_DBGTRACE();

    status = JoinMCastGroup(network);
    if (status != DPS_OK) {
        goto Exit;
    }
    status = BindSock(AF_INET6, network, 0);
    if (status != DPS_OK) {
        goto Exit;
    }
    network->recvCB = cb;

	ret = net_context_recv(network->mcast6, OnData, K_NO_WAIT, node);
	if (ret) {
		DPS_ERRPRINT("Could not register callback\n");
		status = DPS_ERR_NETWORK;
        goto Exit;
	}
	ret = net_context_recv(network->ucast6, OnData, K_NO_WAIT, node);
	if (ret) {
		DPS_ERRPRINT("Could not register callback\n");
		status = DPS_ERR_NETWORK;
        goto Exit;
	}

    node->port = GetPort(network->ucast6);
    DPS_DBGPRINT("Listening on port %d\n", node->port);

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

    DPS_DBGTRACE();

    memset(&addr6, 0, sizeof(addr6));
    ret = net_addr_pton(AF_INET6, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, &addr6.sin6_addr);
    if (ret) {
        return DPS_ERR_NETWORK;
    }
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(COAP_UDP_PORT);

    pkt = net_pkt_get_tx(net->mcast6, K_FOREVER);
    if (!pkt) {
        return DPS_ERR_NETWORK;
    }
    len = net_pkt_append(pkt, len, buf, K_FOREVER);
    if (!len) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
    /* TODO - register completion callback */
    ret = net_context_sendto(pkt, (struct sockaddr*)&addr6, sizeof(addr6), NULL, K_FOREVER, NULL, node);
    if (ret < 0) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
	return DPS_OK;
}

DPS_Status DPS_UnicastSend(DPS_Node* node, DPS_NodeAddress* dest, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Network* net = node->network;
    int ret;
    unsigned int len = (unsigned int)(node->txLen + node->txHdrLen);
    uint8_t* buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;
    struct net_pkt* pkt;

    DPS_DBGTRACE();

    pkt = net_pkt_get_tx(net->ucast6, K_FOREVER);
    if (!pkt) {
        return DPS_ERR_NETWORK;
    }
    len = net_pkt_append(pkt, len, buf, K_FOREVER);
    if (!len) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
    /* TODO - register completion callback */
    ret = net_context_sendto(pkt, (struct sockaddr*)dest, sizeof(struct sockaddr_storage), NULL, K_FOREVER, NULL, node);
    if (ret < 0) {
        /* balances the internal add ref inside net_pkt_get_tx() */
        net_pkt_unref(pkt);
        return DPS_ERR_NETWORK;
    }
	return DPS_OK;
}
