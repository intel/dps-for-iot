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

#include <Winsock2.h>
#include <Mswsock.h>
#include <Ws2ipdef.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

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

#define MAX_MCAST_TX_SOCKS  64

struct _DPS_NodeAddress {
    struct sockaddr_storage inaddr;
};

/* Struct for MCast send */
typedef struct _MCastTx {
    ADDRESS_FAMILY family;
    SOCKET sendSock;
    WSAOVERLAPPED sendOL;
} MCastTx;

#define NUM_RECV_SOCKS  3

typedef enum {
    DTLS_DISABLED,
    DTLS_IN_HANDSHAKE,
    DTLS_CONNECTED
} DTLS_State;

struct _DPS_Network {
    SOCKET mcastRecvSock[2];             /* IPv4 and IPv6 multicast recv sockets */
    SOCKET udpSock;                      /* The UDP unicast socket */ 
    uint8_t rxBuffer[NUM_RECV_SOCKS][RX_BUFFER_SIZE]; /* need separate buffers for each recv socket */
    DTLS_State dtlsState;
    DWORD txLen;
    DPS_OnReceive recvCB;
    uint16_t numMcastTxSocks;
    MCastTx mcastTx[MAX_MCAST_TX_SOCKS];
    struct sockaddr_in addrCOAP4;
    struct sockaddr_in6 addrCOAP6;
    DPS_NodeAddress remoteNode;
    WSAOVERLAPPED sendOL;
    DPS_SendComplete sendCB;
    void* appData;
};

static DPS_Network netContext;

static HANDLE recvThreadHandle;
static HANDLE cbThreadHandle;

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
        memcpy_s(&tmp.sin6_addr, sizeof(tmp.sin6_addr), IP4as6, 12);
        memcpy_s((uint8_t*)&tmp.sin6_addr + 12, sizeof(tmp.sin6_addr) - 12, &ip, 4);
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

static DWORD WINAPI RecvThread(LPVOID lpParam)
{
    DPS_Node* node = (DPS_Node*)lpParam;
    DPS_Network* net = node->network;
    DPS_NodeAddress rxAddr;
    DPS_RxBuffer rxBuf;
    WSAOVERLAPPED overlapped[NUM_RECV_SOCKS];
    WSAEVENT event[NUM_RECV_SOCKS];
    WSABUF buf[NUM_RECV_SOCKS];
    SOCKET socks[NUM_RECV_SOCKS];
    DWORD flags;
    DWORD recvd;
    int ret;
    int i;

    assert(net);
    assert(net->recvCB);

    socks[0] = net->mcastRecvSock[0];
    socks[1] = net->mcastRecvSock[1];
    socks[2] = net->udpSock;

    /* Setup overlapped recv on each of the receive sockets */
    for (i = 0; i < NUM_RECV_SOCKS; ++i) {
        memset(&overlapped[i], 0, sizeof(WSAOVERLAPPED));
        overlapped[i].hEvent = event[i] = WSACreateEvent();
        if (socks[i] != INVALID_SOCKET) {
            buf[i].buf = net->rxBuffer[i];
            buf[i].len = RX_BUFFER_SIZE;
            /* Loop while there is data immediately available */
            while (TRUE) {
                int len = (int)sizeof(rxAddr);
                flags = 0;
                if (WSARecvFrom(socks[i], &buf[i], 1, &recvd, &flags, (SOCKADDR*)&rxAddr, &len, &overlapped[i], NULL)) {
                    break;
                }
                DPS_RxBufferInit(&rxBuf, net->rxBuffer[i], recvd);
                net->recvCB(node, &rxAddr, i <= 1, &rxBuf, DPS_OK);
            }
            if (WSAGetLastError() != WSA_IO_PENDING) {
                DPS_ERRPRINT("WSARecvFrom for %s returned %d\n", i ? "IPv6" : "IPv4", WSAGetLastError());
                socks[i] = INVALID_SOCKET;
            }
        }
    }

    while (net) {
        ret = WSAWaitForMultipleEvents(NUM_RECV_SOCKS, event, FALSE, INFINITE, TRUE);
        if (ret == WSA_WAIT_FAILED) {
            DPS_ERRPRINT("WSAWaitForMultipleEvents failed %d\n", WSAGetLastError());
            break;
        }
        if (ret == WSA_WAIT_IO_COMPLETION) {
            continue;
        }
        i = ret - WSA_WAIT_EVENT_0;
        if (i > NUM_RECV_SOCKS) {
            DPS_ERRPRINT("WSAWaitForMultipleEvents returned unexpected value %d\n", ret);
            goto Exit;
        }
        ret = WSAResetEvent(event[i]);
        if (ret == FALSE) {
            DPS_DBGPRINT("WSAResetEvent failed %d\n", WSAGetLastError());
            goto Exit;
        }
        ret = WSAGetOverlappedResult(socks[i], &overlapped[i], &recvd, TRUE, &flags);
        if (ret == FALSE) {
            DPS_DBGPRINT("WSAGetOverlappedResult failed %d\n", WSAGetLastError());
            goto Exit;
        }
        while (TRUE) {
            int len = (int)sizeof(rxAddr);
            DPS_RxBufferInit(&rxBuf, net->rxBuffer[i], recvd);
            net->recvCB(node, &rxAddr, i <= 1, &rxBuf, DPS_OK);
            flags = 0;
            /* Loop while there is data immediately available */
            if (WSARecvFrom(socks[i], &buf[i], 1, &recvd, &flags, (SOCKADDR*)&rxAddr, &len, &overlapped[i], NULL)) {
                break;
            }
        }
        if (WSAGetLastError() != WSA_IO_PENDING) {
            DPS_DBGPRINT("WSARecvFrom returned %d\n", WSAGetLastError());
        }
    }

    for (i = 0; i < NUM_RECV_SOCKS; ++i) {
        WSACloseEvent(event[i]);
    }

    DPS_DBGPRINT("Exiting %s\n", __FUNCTION__);
    return 0;

Exit:

    DPS_DBGPRINT("Exiting %s on error\n", __FUNCTION__);

    for (i = 0; i < NUM_RECV_SOCKS; ++i) {
        WSACloseEvent(event[i]);
    }

    return -1;
}

/*
 * Thread for monitoring multicast send completion
 */
static DWORD WINAPI MulticastCBThread(LPVOID lpParam)
{
    DPS_Node* node = (DPS_Node*)lpParam;
    DPS_Network* net = node->network;
    WSAEVENT events[MAX_MCAST_TX_SOCKS];
    int i;

    /* Get events into a contiguous array */
    for (i = 0; i < net->numMcastTxSocks; ++i) {
        events[i] = net->mcastTx[i].sendOL.hEvent;
    }
    while (DPS_TRUE) {
        DPS_SendComplete sendCB;
        /* Wait for all of the interfaces to be signaled */
        int ret = WSAWaitForMultipleEvents(net->numMcastTxSocks, events, DPS_TRUE, WSA_INFINITE, DPS_FALSE);
        /* Clear all events an re-prime the overlapped structs */
        for (i = 0; i < net->numMcastTxSocks; ++i) {
            WSAResetEvent(events[i]);
            memset(&net->mcastTx[i].sendOL, 0, sizeof(WSAOVERLAPPED));
            net->mcastTx[i].sendOL.hEvent = events[i];
        }
        sendCB = net->sendCB;
        net->sendCB = NULL;
        if (sendCB) {
            if (ret == WSA_WAIT_FAILED) {
                sendCB(node, net->appData, DPS_ERR_NETWORK);
            } else {
                sendCB(node, net->appData, DPS_OK);
            }
        }
    }
    return 0;
}

/*
 * Thread for monitoring unicast send completion
 */
static DWORD WINAPI UnicastCBThread(LPVOID lpParam)
{
    DPS_Node* node = (DPS_Node*)lpParam;
    DPS_Network* net = node->network;
    WSAEVENT event = net->sendOL.hEvent;
    DPS_SendComplete sendCB;

    /* Wait for all of the interfaces to be signaled */
    int ret = WSAWaitForMultipleEvents(1, &net->sendOL.hEvent, DPS_TRUE, WSA_INFINITE, DPS_FALSE);
    /* Clear all events an re-prime the overlapped structs */
    WSAResetEvent(event);
    memset(&net->sendOL, 0, sizeof(WSAOVERLAPPED));
    net->sendOL.hEvent = event;

    sendCB = net->sendCB;
    net->sendCB = NULL;
    if (sendCB) {
        if (ret == WSA_WAIT_FAILED) {
            sendCB(node, net->appData, DPS_ERR_NETWORK);
        } else {
            sendCB(node, net->appData, DPS_OK);
        }
    }
    return 0;
}

static SOCKET BindSock(int family, int port)
{
    int ret = 0;
    SOCKET sock;

    sock = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        DPS_ERRPRINT("%s: WSASocketW() failed. WSAGetLastError()=0x%x\n", __FUNCTION__, WSAGetLastError());
    } else {
        ULONG yes = 1;
        /* Set SO_REUSEADDR on the socket. */
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
        if (ret == SOCKET_ERROR) {
            DPS_ERRPRINT("%s: setsockopt SO_REUSEADDR failed. WSAGetLastError()=0x%x\n", __FUNCTION__, WSAGetLastError());
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
        if (ret == SOCKET_ERROR) {
            DPS_ERRPRINT("%s: bind() %s failed. %d\n", __FUNCTION__, family == AF_INET ? "IPv4" : "IPv6", WSAGetLastError());
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }
    return sock;
}

DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;
    struct sockaddr_storage addr;
    WSADATA wsaData;
    WORD version = MAKEWORD(2, 0);
    int addrSize = sizeof(addr);
    int ret = WSAStartup(version, &wsaData);
    if (ret) {
        DPS_ERRPRINT("WSAStartup failed with error: %d\n", ret);
        return DPS_ERR_NETWORK;
    }
    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;
    node->remoteNode = &netContext.remoteNode;

    node->network->udpSock = BindSock(AF_INET6, 0);
    ret = getsockname(node->network->udpSock, (struct sockaddr*)&addr, &addrSize);
    if (ret) {
        DPS_ERRPRINT("getsockname() failed with error: %d\n", WSAGetLastError());
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
    WSACleanup();
}

static PIP_ADAPTER_ADDRESSES GetAdapters()
{
    int ret;
    ULONG sz = 0;
    PIP_ADAPTER_ADDRESSES adapters;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    /* Call with null buffer to get required size */
    ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &sz);
    assert(ret == ERROR_BUFFER_OVERFLOW);
    /* Now we can get the adapter list */
    adapters = malloc(sz);
    if (adapters) {
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &sz);
        if (ret != ERROR_SUCCESS) {
            free(adapters);
            adapters = NULL;
        }
    }
    return adapters;
}

DPS_Status DPS_NetworkStart(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Network* network = node->network;
    struct addrinfo hints;
    INT ret;
    GROUP_REQ req4;
    GROUP_REQ req6;
    PIP_ADAPTER_ADDRESSES adapterList = NULL;
    PIP_ADAPTER_ADDRESSES adapter;

    /* Bind the IPv4 and IPv6 recv sockets */
    network->mcastRecvSock[IPV4] = BindSock(AF_INET, COAP_UDP_PORT);
    network->mcastRecvSock[IPV6] = BindSock(AF_INET6, COAP_UDP_PORT);

    /* OK if we have at least one network family */
    if (network->mcastRecvSock[IPV4] == INVALID_SOCKET && network->mcastRecvSock[IPV6] == INVALID_SOCKET) {
        return DPS_ERR_NETWORK;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    /* Configure the IPv4 request */
    if (network->mcastRecvSock[IPV4] != INVALID_SOCKET) {
        struct addrinfo* ai;
        hints.ai_flags = AF_INET;
        ret = getaddrinfo(COAP_MCAST_ALL_NODES_LINK_LOCAL_4, "0", &hints, &ai);
        if (ret != 0) {
            DPS_DBGPRINT("getaddrinfo failed (%d)\n", WSAGetLastError());
            goto ErrorExit;
        }
        memcpy(&req4.gr_group, ai->ai_addr, ai->ai_addrlen);
        /* Save the COAP destination address */
        memcpy(&network->addrCOAP4, ai->ai_addr, ai->ai_addrlen);
        network->addrCOAP4.sin_port = htons(COAP_UDP_PORT);
        freeaddrinfo(ai);
    }
    /* Configure the IPv6 request */
    if (network->mcastRecvSock[IPV6] != INVALID_SOCKET) {
        struct addrinfo* ai;
        hints.ai_flags = AF_INET;
        ret = getaddrinfo(COAP_MCAST_ALL_NODES_LINK_LOCAL_6, "0", &hints, &ai);
        if (ret != 0) {
            DPS_DBGPRINT("getaddrinfo failed (%d)\n", WSAGetLastError());
            goto ErrorExit;
        }
        memcpy(&req6.gr_group, ai->ai_addr, ai->ai_addrlen);
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
    for (adapter = adapterList; adapter; adapter = adapter->Next) {
        PIP_ADAPTER_UNICAST_ADDRESS_LH addr;
        /* Skip adapters that are not up */
        if (adapter->OperStatus != IfOperStatusUp || adapter->FirstUnicastAddress == NULL) {
            continue;
        }
        DPS_DBGPRINT("Configure MCAST receive on %wS index=%d\n", adapter->FriendlyName, adapter->IfIndex);
        if (network->mcastRecvSock[IPV4] != INVALID_SOCKET) {
            req4.gr_interface = adapter->IfIndex;
            ret = setsockopt(network->mcastRecvSock[IPV4], IPPROTO_IP, MCAST_JOIN_GROUP, (char*)&req4, sizeof(req4));
            if (ret == SOCKET_ERROR) {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv4 failed (%d)\n", WSAGetLastError());
            } else {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv4 sucessful\n");
            }
        }
        if (network->mcastRecvSock[IPV6] != INVALID_SOCKET) {
            req6.gr_interface = adapter->IfIndex;
            ret = setsockopt(network->mcastRecvSock[IPV6], IPPROTO_IPV6, MCAST_JOIN_GROUP, (char*)&req6, sizeof(req6));
            if (ret == SOCKET_ERROR) {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv6 failed (%d)\n", WSAGetLastError());
            } else {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv6 sucessful\n");
            }
        }
        /* Accumulate addresses for multicast send */
        for (addr = adapter->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
            SOCKET sock;
            struct sockaddr* sa = addr->Address.lpSockaddr;
            if (network->numMcastTxSocks >= MAX_MCAST_TX_SOCKS) {
                DPS_DBGPRINT("Too many interfaces\n");
                break;
            }
            MCastTx* mtx = &network->mcastTx[network->numMcastTxSocks];
            mtx->family = sa->sa_family;
            mtx->sendOL.hEvent = WSACreateEvent();

            /* Bind a send socket for this interface */
            sock = BindSock(mtx->family, 0);

            if (mtx->family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
                ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id));
                if (ret == SOCKET_ERROR) {
                    DPS_ERRPRINT("setsockopt IP_MULICAST_IF failed %d\n", WSAGetLastError());
                }
            } else {
                struct sockaddr_in* sin = (struct sockaddr_in*)sa;
                ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&sin->sin_addr, sizeof(sin->sin_addr));
                if (ret == SOCKET_ERROR) {
                    DPS_ERRPRINT("setsockopt IP_MULICAST_IF failed %d\n", WSAGetLastError());
                }
            }
            if (ret == SOCKET_ERROR) {
                closesocket(sock);
            } else {
                mtx->sendSock = sock;
                ++network->numMcastTxSocks;
            }
        }
    }
    network->recvCB = cb;
    free(adapterList);
    adapterList = NULL;
    /* We need at least one interface for sending multicast data */
    if (network->numMcastTxSocks == 0) {
        DPS_ERRPRINT("Failed to configure multicast on any interface\n");
        goto ErrorExit;
    }
    /* Start the recv thread */
    recvThreadHandle = CreateThread(NULL, 0, RecvThread, node, 0, NULL);
    if (recvThreadHandle == NULL) {
        DPS_ERRPRINT("Failed to start multicast receive thread\n");
        goto ErrorExit;
    }
    /* Start the multicast send completion thread */
    cbThreadHandle = CreateThread(NULL, 0, MulticastCBThread, node, 0, NULL);
    if (cbThreadHandle == NULL) {
        DPS_ERRPRINT("Failed to start multicast send completion thread\n");
        goto ErrorExit;
    }
    /* Start the unicast send completion thread */
    cbThreadHandle = CreateThread(NULL, 0, UnicastCBThread, node, 0, NULL);
    if (cbThreadHandle == NULL) {
        DPS_ERRPRINT("Failed to start unicast send completion thread\n");
        goto ErrorExit;
    }
    return DPS_OK;

ErrorExit:

    if (adapterList) {
        free(adapterList);
    }
    closesocket(node->network->mcastRecvSock[IPV4]);
    closesocket(node->network->mcastRecvSock[IPV6]);

    return DPS_ERR_NETWORK;

}

DPS_Status DPS_MCastSend(DPS_Node* node, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Network* net = node->network;
    WSABUF buf;
    int i;

    if (net->sendCB) {
        return DPS_ERR_BUSY;
    }

    buf.len = (LONG)(node->txLen + node->txHdrLen);
    buf.buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;

    net->sendCB = sendCompleteCB;
    net->appData = appCtx;
    /*
     * Multicast on each interface
     */
    for (i = 0; i < net->numMcastTxSocks; ++i) {
        int ret;
        MCastTx* mtx = &net->mcastTx[i];
        if (mtx->family == AF_INET6) {
            ret = WSASendTo(mtx->sendSock, &buf, 1, NULL, 0, (SOCKADDR*)&net->addrCOAP6, sizeof(net->addrCOAP6), &mtx->sendOL, NULL);
        } else {
            ret = WSASendTo(mtx->sendSock, &buf, 1, NULL, 0, (SOCKADDR*)&net->addrCOAP4, sizeof(net->addrCOAP4), &mtx->sendOL, NULL);
        }
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSA_IO_PENDING) {
                DPS_DBGPRINT("WSASEndTo I/O pending\n");
            } else {
                DPS_ERRPRINT("WSASEndTo failed %d\n", err);
                /* Set the event for the callback thread */
                WSASetEvent(mtx->sendOL.hEvent);
            }
        }
    }
    return DPS_OK;
}

static void CALLBACK UnicastSendComplete(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED lpOverlapped, DWORD dwFlags)
{
    DPS_Node* node = (DPS_Node*)lpOverlapped->hEvent;
    DPS_Network* net = node->network;
    DPS_SendComplete cb = net->sendCB;

    net->sendCB = NULL;
    cb(node, net->appData, dwError ? DPS_ERR_NETWORK : DPS_OK);
}

DPS_Status DPS_UnicastSend(DPS_Node* node, DPS_NodeAddress* dest, void* appCtx, DPS_SendComplete sendCompleteCB)
{
    DPS_Status status = DPS_OK;
    DPS_Network* net = node->network;

    if (net->sendCB) {
        return DPS_ERR_BUSY;
    }
    net->sendCB = sendCompleteCB;
    net->appData = appCtx;

    if (net->dtlsState == DTLS_DISABLED || net->dtlsState == DTLS_CONNECTED) {
        int ret;
        WSABUF buf;

        buf.len = (LONG)(node->txLen + node->txHdrLen);
        buf.buf = node->txBuffer + DPS_TX_HEADER_SIZE - node->txHdrLen;

        ret = WSASendTo(net->udpSock, &buf, 1, NULL, 0, (SOCKADDR*)dest, sizeof(DPS_NodeAddress), &net->sendOL, NULL);
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                DPS_ERRPRINT("WSASEndTo failed %d\n", err);
                status = DPS_ERR_NETWORK;
            }
        }
    }
    if (status != DPS_OK) {
        net->sendCB = NULL;
        net->appData = NULL;
    }
    return status;
}
