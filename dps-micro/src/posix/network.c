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
#include <dps/private/dtls.h>
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

#define NUM_RECV_SOCKS  3

struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
};

struct _DPS_Network {
    int mcastRecvSock[2];             /* IPv4 and IPv6 sockets */
    int mcastSendSock[2];             /* IPv4 and IPv6 sockets */
    int udpSock;                      /* The UDP unicast socket */
    uint8_t rxBuffer[RX_BUFFER_SIZE];
    size_t txLen;
    DPS_OnReceive recvCB;
    uint16_t numMcastIfs;
    InterfaceSpec mcastIf[MAX_MCAST_INTERFACES];
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
    DPS_NodeAddress remoteNode;
    DPS_SendComplete sendCB;
    void* appData;
    DPS_DTLS dtls;
};

static DPS_Network netContext;

static pthread_t recvThreadHandle;
static pthread_t unicastCBThreadHandle;

const char* DPS_AddrToText(const DPS_NodeAddress* addr)
{
    static char txt[INET6_ADDRSTRLEN];

    if (addr->inaddr.ss_family == AF_INET) {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr->inaddr;
        return inet_ntop(AF_INET, &sa4->sin_addr, txt, sizeof(txt));
    } else {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr->inaddr;
        return inet_ntop(AF_INET6, &sa6->sin6_addr, txt, sizeof(txt));
    }
}

const DPS_NodeAddress* DPS_TextToAddr(const char* addrStr, uint16_t port)
{
    static DPS_NodeAddress addr;
    int family = AF_INET;
    int ret;

    if (addrStr) {
        const char* p = addrStr;
        while (*p) {
            if (*p++ == ':') {
                family = AF_INET6;
                break;
            }
        }
    } else {
        family = AF_INET6;
        addrStr = "::1";
    }

    memset(&addr, 0, sizeof(DPS_NodeAddress));

    if (family == AF_INET) {
        struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr.inaddr;
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        ret = inet_pton(family, addrStr, &sa4->sin_addr);
    } else {
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr.inaddr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        ret = inet_pton(family, addrStr, &sa6->sin6_addr);
    }
    if (ret <= 0) {
        if (ret < 1) {
            DPS_ERRPRINT("InetPton returned %d\n", errno);
        }
        return NULL;
    } else {
        return &addr;
    }
}

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

static void* RecvThread(void* arg)
{
    DPS_Node* node = (DPS_Node*)arg;
    DPS_Network* net = node->network;
    DPS_RxBuffer rxBuf;
    int epfd = -1;
    int socks[NUM_RECV_SOCKS];
    int ret;
    int i;

    assert(net);
    assert(net->recvCB);

    socks[0] = net->mcastRecvSock[0];
    socks[1] = net->mcastRecvSock[1];
    socks[2] = net->udpSock;

    epfd = epoll_create(NUM_RECV_SOCKS);
    if (epfd == -1) {
        DPS_DBGPRINT("epoll_create failed with error: %d\n", errno);
        goto Exit;
    }

    /* Setup polling on each of the receive sockets */
    for (i = 0; i < NUM_RECV_SOCKS; ++i) {
        if (socks[i] != -1) {
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.fd = socks[i];
            ret = epoll_ctl(epfd, EPOLL_CTL_ADD, socks[i], &ev);
            if (ret == -1) {
                DPS_DBGPRINT("epoll_ctl failed with error: %d\n", errno);
                goto Exit;
            }
        }
    }

    while (net) {
        struct epoll_event events[NUM_RECV_SOCKS];
        int nfds = epoll_wait(epfd, events, NUM_RECV_SOCKS, -1);
        if (nfds == -1) {
            DPS_DBGPRINT("epoll_wait failed with error: %d\n", errno);
            break;
        }
        for (i = 0; i < nfds; ++i) {
            DPS_NodeAddress rxAddr;
            socklen_t addrLen = sizeof(rxAddr);
            DPS_Status status = DPS_OK;
            int multicast = (events[i].data.fd != net->udpSock);
            ret = recvfrom(events[i].data.fd, net->rxBuffer, RX_BUFFER_SIZE, 0, (struct sockaddr*)&rxAddr, &addrLen);
            if (ret == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    DPS_DBGPRINT("recv failed with error: %d\n", errno);
                    goto Exit;
                }
            } else {
                DPS_RxBufferInit(&rxBuf, net->rxBuffer, ret);
                if (!multicast && net->dtls.state != DTLS_DISABLED) {
                    status = DPS_DTLSRecv(node, &rxAddr, &rxBuf);
                }
                if (status != DPS_ERR_NO_DATA) {
                    net->recvCB(node, &rxAddr, multicast, &rxBuf, status);
                }
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

static void* UnicastCBThread(void* arg)
{
    DPS_Node* node = (DPS_Node*)arg;
    DPS_Network* net = node->network;
    struct epoll_event event;
    int epfd = -1;
    int ret;

    epfd = epoll_create(1);
    if (epfd == -1) {
        DPS_DBGPRINT("epoll_create failed with error: %d\n", errno);
        return NULL;
    }
    event.events = EPOLLOUT;
    event.data.fd = net->udpSock;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, net->udpSock, &event);
    if (ret == -1) {
        DPS_DBGPRINT("epoll_ctl failed with error: %d\n", errno);
        return NULL;
    }

    while (DPS_TRUE) {
        int nfds = epoll_wait(epfd, &event, 1, -1);
        if (nfds == -1) {
            DPS_DBGPRINT("epoll_wait failed with error: %d\n", errno);
            break;
        }
        /* Ignore completion while we are in the DTLS handshake */
        if (net->dtls.state != DTLS_IN_HANDSHAKE) {
            DPS_SendComplete sendCB = net->sendCB;
            net->sendCB = NULL;
            if (sendCB) {
                sendCB(node, net->appData, DPS_OK);
            }
        }
    }
    return NULL;
}

static int BindSock(int family, int port)
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

DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;
    struct sockaddr_storage addr;
    int ret;
    socklen_t addrSize = sizeof(addr);

    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;
    node->remoteNode = &netContext.remoteNode;

    /* By default DTLS is enabled and we are in the DTLS disconnected state */
    node->network->dtls.state = DTLS_DISCONNECTED;

    node->network->udpSock = BindSock(AF_INET6, 0);
    ret = getsockname(node->network->udpSock, (struct sockaddr*)&addr, &addrSize);
    if (ret) {
        DPS_ERRPRINT("getsockname() failed with error: %d\n", errno);
        status = DPS_ERR_NETWORK;
    } else {
        if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6* sa6 = (struct sockaddr_in6*)&addr;
            node->port = ntohs(sa6->sin6_port);
        } else {
            struct sockaddr_in* sa4 = (struct sockaddr_in*)&addr;
            node->port = ntohs(sa4->sin_port);
        }
        DPS_DBGPRINT("Network listening on port %d\n", node->port);
    }
    return status;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
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

DPS_Status DPS_NetworkStart(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Network* network = node->network;
    struct addrinfo hints;
    int ret;
    struct ip_mreqn req4;
    struct ipv6_mreq req6;
    struct ifaddrs* adapterList = NULL;
    struct ifaddrs* adapter;

    /* Bind the IPv4 and IPv6 recv sockets */
    network->mcastRecvSock[IPV4] = BindSock(AF_INET, COAP_UDP_PORT);
    network->mcastRecvSock[IPV6] = BindSock(AF_INET6, COAP_UDP_PORT);

    network->mcastSendSock[IPV4] = BindSock(AF_INET, 0);
    network->mcastSendSock[IPV6] = BindSock(AF_INET6, 0);

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
    network->recvCB = cb;
    freeifaddrs(adapterList);
    adapterList = NULL;

    /* Start the multicast recv thread */
    ret = pthread_create(&recvThreadHandle, NULL, RecvThread, node);
    if (ret) {
        DPS_DBGPRINT("Failed to start multicast receive thread\n");
        goto ErrorExit;
    }
    /* Start the write completion thread */
    ret = pthread_create(&unicastCBThreadHandle, NULL, UnicastCBThread, node);
    if (ret) {
        DPS_DBGPRINT("Failed to start unicast send complete thread\n");
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

DPS_Status DPS_UnicastWriteAsync(DPS_Node* node, const DPS_NodeAddress* dest, void* data, size_t len)
{
    DPS_Status status = DPS_OK;
    DPS_Network* net = node->network;
    int ret;

    DPS_DBGTRACE();
    DPS_DBGPRINT("Writing %d bytes\n", len);

    ret = sendto(net->udpSock, data, len, 0, (const struct sockaddr*)dest, sizeof(DPS_NodeAddress));
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            DPS_DBGPRINT("sendto failed with error: %d\n", errno);
            status = DPS_ERR_NETWORK;
        }
    }
    return status;
}

DPS_Status DPS_UnicastSend(DPS_Node* node, const DPS_NodeAddress* dest, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Status status = DPS_OK;
    DPS_Network* net = node->network;

    DPS_DBGTRACE();
    DPS_DBGPRINT("DTLS state = %d\n", net->dtls.state);

    if (net->sendCB) {
        return DPS_ERR_BUSY;
    }

    net->sendCB = sendCompleteCB;
    net->appData = appCtx;

    switch (net->dtls.state) {
    case DTLS_DISABLED:
        /*
         * DTLS is not being used
         */
        {
            size_t len = (node->txLen + node->txHdrLen);
            void* data = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;
            status = DPS_UnicastWriteAsync(node, dest, data, len);
        }
        break;
    case DTLS_DISCONNECTED:
        /*
         * This kicks off the DTLS client-side handshake
         */
        status = DPS_DTLSStartHandshake(node, dest, MBEDTLS_SSL_IS_CLIENT);
        break;
    case DTLS_CONNECTED:
        /*
         * DTLS needs to encrypt the packet
         */
        status = DPS_DTLSSend(node);
        break;
    case DTLS_IN_HANDSHAKE:
        /*
         * Already in a server side handshake due to an incoming packet
         */
        status = DPS_ERR_BUSY;
        break;
    }
    if (status != DPS_OK) {
        net->sendCB = NULL;
        net->appData = NULL;
    }
    return status;
}

int DPS_UnicastWritePending(DPS_Network* net)
{
    return net->sendCB != NULL;
}

DPS_DTLS* DPS_GetDTLS(DPS_Network* net)
{
    if (net) {
        return &net->dtls;
    } else {
        return NULL;
    }
}
