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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

#define MAX_MCAST_INTERFACES  64

/* Identifies which interface to send on */
typedef struct _InterfaceSpec {
    sa_family_t family;
    union {
        uint32_t scope_id; /* for IPv6 */
        uint32_t addr;   /* IPv4 address */
    };
} InterfaceSpec;

struct _DPS_Network {
    int mcastRecvSock[2];             /* IPv4 and IPv6 sockets */
    int mcastSendSock[2];             /* IPv4 and IPv6 sockets */
    uint8_t rxBuffer[RX_BUFFER_SIZE];
    size_t txLen;
    DPS_OnReceive mcastRecvCB;
    DPS_OnReceive recvCB;
    uint16_t numMcastIfs;
    InterfaceSpec mcastIf[MAX_MCAST_INTERFACES];
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
};

static DPS_Network netContext;

static pthread_t recvThreadHandle;

static void* MCastRecvThread(void* lpParam)
{
    DPS_Node* node = (DPS_Node*)lpParam;
    DPS_Network* net = node->network;
    DPS_RxBuffer rxBuf;
    int epfd = -1;
    struct epoll_event events[2];
    int nfds;
    int ret;
    int i;

    assert(net);
    assert(net->mcastRecvCB);

    epfd = epoll_create(2);
    if (epfd == -1) {
        DPS_DBGPRINT("epoll_create failed with error: %d\n", errno);
        goto Exit;
    }

    /* Setup overlapped recv on IPv4 and IPv6 sockets */
    for (i = 0; i < 2; ++i) {
        if (net->mcastRecvSock[i] != -1) {
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.fd = net->mcastRecvSock[i];
            ret = epoll_ctl(epfd, EPOLL_CTL_ADD, net->mcastRecvSock[i], &ev);
            if (ret == -1) {
                DPS_DBGPRINT("epoll_ctl failed with error: %d\n", errno);
                goto Exit;
            }
        }
    }

    while (net && net->mcastRecvCB) {
        nfds = epoll_wait(epfd, events, 2, -1);
        if (nfds == -1) {
            DPS_DBGPRINT("epoll_wait failed with error: %d\n", errno);
            break;
        }

        for (i = 0; i < nfds; ++i) {
            ret = recv(events[i].data.fd, net->rxBuffer, RX_BUFFER_SIZE, 0);
            if (ret == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    DPS_DBGPRINT("recv failed with error: %d\n", errno);
                    goto Exit;
                }
            } else {
                DPS_RxBufferInit(&rxBuf, net->rxBuffer, ret);
                net->mcastRecvCB(node, &rxBuf, DPS_OK);
            }
        }
    }

    close(epfd);

    DPS_DBGPRINT("Exiting %s\n", __FUNCTION__);
    return 0;

Exit:

    DPS_DBGPRINT("Exiting %s on error\n", __FUNCTION__);

    if (epfd != -1) {
        close(epfd);
    }

    return (void*)-1;
}


DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;
    return DPS_OK;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
}

static int BindSock(int family, DPS_Network* net, int port)
{
    int ret = 0;
    int sock;

    sock = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock == -1) {
        DPS_DBGPRINT("%s: socket() failed with error: %d\n", __FUNCTION__, errno);
    } else {
        int yes = 1;
        /* Set SO_REUSEADDR on the socket. */
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (ret == -1) {
            DPS_DBGPRINT("%s: setsockopt SO_REUSEADDR failed with error: %d\n", __FUNCTION__, errno);
        }
        if (family == AF_INET) {
            struct sockaddr_in addrAny4;
            memset(&addrAny4, 0, sizeof(addrAny4));
            addrAny4.sin_family = AF_INET;
            addrAny4.sin_addr.s_addr = INADDR_ANY;
            addrAny4.sin_port = htons(port);
            ret = bind(sock, (struct sockaddr*)&addrAny4, sizeof(addrAny4));
        } else {
            struct sockaddr_in6 addrAny6;
            memset(&addrAny6, 0, sizeof(addrAny6));
            addrAny6.sin6_port = htons(port);
            addrAny6.sin6_family = AF_INET6;
            addrAny6.sin6_addr = in6addr_any;
            ret = bind(sock, (struct sockaddr*)&addrAny6, sizeof(addrAny6));
        }
        if (ret == -1) {
            DPS_DBGPRINT("%s: bind() %s failed with error: %d\n", __FUNCTION__, family == AF_INET ? "IPv4" : "IPv6", errno);
            close(sock);
            sock = -1;
        }
    }
    return sock;
}

static struct ifaddrs* GetAdapters()
{
    struct ifaddrs* addrs;
    int ret;

    ret = getifaddrs(&addrs);
    if (ret == -1) {
        addrs = NULL;
    }
    return addrs;
}

DPS_Status DPS_MCastStart(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Network* network = node->network;
    struct addrinfo hints;
    int ret;
    struct ip_mreqn req4;
    struct ipv6_mreq req6;
    struct ifaddrs* adapterList = NULL;
    struct ifaddrs* adapter;

    /* Bind the IPv4 and IPv6 recv sockets */
    network->mcastRecvSock[IPV4] = BindSock(AF_INET, network, COAP_UDP_PORT);
    network->mcastRecvSock[IPV6] = BindSock(AF_INET6, network, COAP_UDP_PORT);

    network->mcastSendSock[IPV4] = BindSock(AF_INET, network, 0);
    network->mcastSendSock[IPV6] = BindSock(AF_INET6, network, 0);

    /* OK if we have at least one network family */
    if (network->mcastRecvSock[IPV4] == -1 && network->mcastRecvSock[IPV6] == -1) {
        return DPS_ERR_NETWORK;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    /* Configure the IPv4 request */
    if (network->mcastRecvSock[IPV4] != -1) {
        struct addrinfo* ai;
        hints.ai_flags = AF_INET;
        ret = getaddrinfo(COAP_MCAST_ALL_NODES_LINK_LOCAL_4, "0", &hints, &ai);
        if (ret != 0) {
            DPS_DBGPRINT("getaddrinfo failed with error: %d\n", errno);
            goto ErrorExit;
        }
        memcpy(&req4.imr_multiaddr, &((struct sockaddr_in*)ai->ai_addr)->sin_addr, sizeof(req4.imr_multiaddr));
        /* Save the COAP destination address */
        memcpy(&network->addrCOAP4, ai->ai_addr, ai->ai_addrlen);
        network->addrCOAP4.sin_port = htons(COAP_UDP_PORT);
        freeaddrinfo(ai);
    }
    /* Configure the IPv6 request */
    if (network->mcastRecvSock[IPV6] != -1) {
        struct addrinfo* ai;
        hints.ai_flags = AF_INET;
        ret = getaddrinfo(COAP_MCAST_ALL_NODES_LINK_LOCAL_6, "0", &hints, &ai);
        if (ret != 0) {
            DPS_DBGPRINT("getaddrinfo failed with error: %d\n", errno);
            goto ErrorExit;
        }
        memcpy(&req6.ipv6mr_multiaddr, &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr, sizeof(req6.ipv6mr_multiaddr));
        /* Save the COAP destination address */
        memcpy(&network->addrCOAP6, ai->ai_addr, ai->ai_addrlen);
        network->addrCOAP6.sin6_port = htons(COAP_UDP_PORT);
        freeaddrinfo(ai);
    }
    /* Get the network interfaces and set up the multicast groups */
    adapterList = GetAdapters();
    if (!adapterList) {
        goto ErrorExit;
    }
    /* Adapters is returned as a linked list */
    for (adapter = adapterList; adapter; adapter = adapter->ifa_next) {
        /* Skip adapters that are not up, etc. */
        if ((adapter->ifa_flags & (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) != (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) {
            continue;
        }
        if (!adapter->ifa_addr) {
            continue;
        }
        if (adapter->ifa_addr->sa_family != AF_INET && adapter->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        DPS_DBGPRINT("Configure MCAST receive on %s index=%d\n", adapter->ifa_name, if_nametoindex(adapter->ifa_name));
        if (adapter->ifa_addr->sa_family == AF_INET && network->mcastRecvSock[IPV4] != -1) {
            memcpy(&req4.imr_address, &((struct sockaddr_in*)adapter->ifa_addr)->sin_addr, sizeof(req4.imr_address));
            req4.imr_ifindex = if_nametoindex(adapter->ifa_name);
            ret = setsockopt(network->mcastRecvSock[IPV4], IPPROTO_IP, IP_ADD_MEMBERSHIP, &req4, sizeof(req4));
            if (ret == -1) {
                DPS_DBGPRINT("IP_ADD_MEMBERSHIP failed with error: %d\n", errno);
            } else {
                DPS_DBGPRINT("IP_ADD_MEMBERSHIP sucessful\n");
            }
        } else if (adapter->ifa_addr->sa_family == AF_INET6 && network->mcastRecvSock[IPV6] != -1) {
            req6.ipv6mr_interface = if_nametoindex(adapter->ifa_name);
            ret = setsockopt(network->mcastRecvSock[IPV6], IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req6, sizeof(req6));
            if (ret == -1) {
                DPS_DBGPRINT("IPV6_ADD_MEMBERSHIP failed with error: %d\n", errno);
            } else {
                DPS_DBGPRINT("IPV6_ADD_MEMBERSHIP sucessful\n");
            }
        }
        /* Accumulate addresses for multicast send */
        struct sockaddr* sa = adapter->ifa_addr;
        if (network->numMcastIfs >= MAX_MCAST_INTERFACES) {
            DPS_DBGPRINT("Too many interfaces\n");
            break;
        }
        InterfaceSpec* ifs = &network->mcastIf[network->numMcastIfs];
        ifs->family = sa->sa_family;
        if (sa->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
            ifs->scope_id = sin6->sin6_scope_id;
        } else if (sa->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa;
            memcpy(&ifs->addr, &sin->sin_addr, sizeof(ifs->addr));
        }
        ++network->numMcastIfs;
    }
    network->mcastRecvCB = cb;
    freeifaddrs(adapterList);
    adapterList = NULL;

    /* Start the multicast recv thread */
    ret = pthread_create(&recvThreadHandle, NULL, MCastRecvThread, node);
    if (ret) {
        DPS_DBGPRINT("Failed to start multicast receive thread\n");
        goto ErrorExit;
    }

    return DPS_OK;

ErrorExit:

    if (adapterList) {
        freeifaddrs(adapterList);
    }
    close(node->network->mcastRecvSock[IPV4]);
    close(node->network->mcastRecvSock[IPV6]);

    return DPS_ERR_NETWORK;

}

DPS_Status DPS_MCastSend(DPS_Node* node, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Network* net = node->network;
    size_t len = node->txLen + node->txHdrLen;
    void* buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;
    int ret;
    int i;

    for (i = 0; i < net->numMcastIfs; ++i) {
        InterfaceSpec* ifs = &net->mcastIf[i];
        if (net->mcastIf[i].family == AF_INET6) {
            ret = setsockopt(net->mcastSendSock[IPV6], IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&ifs->scope_id, sizeof(ifs->scope_id));
            if (ret == -1) {
                DPS_DBGPRINT("setsockopt IP_MULICAST_IF failed with error: %d\n", errno);
            } else {
                ret = sendto(net->mcastSendSock[IPV6], buf, len, 0, (const struct sockaddr*)&net->addrCOAP6, sizeof(net->addrCOAP6));
            }
        } else {
            ret = setsockopt(net->mcastSendSock[IPV4], IPPROTO_IP, IP_MULTICAST_IF, (char*)&ifs->addr, sizeof(ifs->addr));
            if (ret == -1) {
                DPS_DBGPRINT("setsockopt IP_MULICAST_IF failed with error: %d\n", errno);
            } else {
                ret = sendto(net->mcastSendSock[IPV4], buf, len, 0, (const struct sockaddr*)&net->addrCOAP4, sizeof(net->addrCOAP4));
            }
        }
        if (ret == -1) {
            DPS_DBGPRINT("sendto failed with error: %d\n", errno);
        }
    }
    return DPS_OK;
}
