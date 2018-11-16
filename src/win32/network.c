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
#include <dps/private/coap.h>
#include <dps/private/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define RX_BUFFER_SIZE 2048
#define TX_BUFFER_SIZE 2048

#define IPV4  0
#define IPV6  1

struct _DPS_Network {
    SOCKET mcastRecvSock[2];             /* IPv4 and IPv6 sockets */
    uint8_t rxBuffer[2][RX_BUFFER_SIZE]; /* need separate buffers for each recv socket */
    uint8_t txBuffer[TX_BUFFER_SIZE];
    DWORD txLen;
    DPS_OnReceive mcastRecvCB;
    DPS_OnReceive recvCB;
};

static DPS_Network netContext;

static HANDLE recvThreadHandle;

static DWORD WINAPI MCastRecvThread(LPVOID lpParam)
{
    DPS_Node* node = (DPS_Node*)lpParam;
    DPS_Network* net = node->network;
    DPS_RxBuffer rxBuf;
    WSAOVERLAPPED overlapped[2];
    WSAEVENT event[2];
    WSABUF buf[2];
    DWORD flags;
    DWORD recvd;
    int ret;
    int i;

    assert(net);
    assert(net->mcastRecvCB);

    /* Setup overlapped recv on IPv4 and IPv6 sockets */
    for (i = 0; i < 2; ++i) {
        memset(&overlapped[i], 0, sizeof(WSAOVERLAPPED));
        overlapped[i].hEvent = event[i] = WSACreateEvent();
        if (net->mcastRecvSock[i] != INVALID_SOCKET) {
            buf[i].buf = net->rxBuffer[i];
            buf[i].len = RX_BUFFER_SIZE;
            /* Loop while there is data immediately available */
            while (TRUE) {
                flags = 0;
                if (WSARecvFrom(net->mcastRecvSock[i], &buf[i], 1, &recvd, &flags, NULL, NULL, &overlapped[i], NULL)) {
                    break;
                }
                DPS_RxBufferInit(&rxBuf, net->rxBuffer[i], recvd);
                net->mcastRecvCB(node, &rxBuf, DPS_OK);
            }
            if (WSAGetLastError() != WSA_IO_PENDING) {
                DPS_DBGPRINT("WSARecvFrom for %s returned %d\n", i ? "IPv6" : "IPv4", WSAGetLastError());
                closesocket(net->mcastRecvSock[i]);
                net->mcastRecvSock[i] = INVALID_SOCKET;
            }
        }
    }

    while (net && net->mcastRecvCB) {
        ret = WSAWaitForMultipleEvents(2, event, FALSE, INFINITE, TRUE);
        if (ret == WSA_WAIT_FAILED) {
            DPS_DBGPRINT("WSAWaitForMultipleEvents failed %d\n", WSAGetLastError());
            break;
        }
        if (ret == WSA_WAIT_IO_COMPLETION) {
            continue;
        }
        i = ret - WSA_WAIT_EVENT_0;
        if (i > 2) {
            DPS_DBGPRINT("WSAWaitForMultipleEvents returned unexpected value %d\n", ret);
            goto Exit;
        }
        ret = WSAResetEvent(event[i]);
        if (ret == FALSE) {
            DPS_DBGPRINT("WSAResetEvent failed %d\n", WSAGetLastError());
            goto Exit;
        }
        ret = WSAGetOverlappedResult(net->mcastRecvSock[i], &overlapped[i], &recvd, TRUE, &flags);
        if (ret == FALSE) {
            DPS_DBGPRINT("WSAGetOverlappedResult failed %d\n", WSAGetLastError());
            goto Exit;
        }
        while (TRUE) {
            DPS_RxBufferInit(&rxBuf, net->rxBuffer[i], recvd);
            net->mcastRecvCB(node, &rxBuf, DPS_OK);
            flags = 0;
            /* Loop while there is data immediately available */
            if (WSARecvFrom(net->mcastRecvSock[i], &buf[i], 1, &recvd, &flags, NULL, NULL, &overlapped[i], NULL)) {
                break;
            }
        }
        if (WSAGetLastError() != WSA_IO_PENDING) {
            DPS_DBGPRINT("WSARecvFrom returned %d\n", WSAGetLastError());
            goto Exit;
        }

    }

    WSACloseEvent(event[0]);
    WSACloseEvent(event[1]);

    DPS_DBGPRINT("Exiting %s\n", __FUNCTION__);
    return 0;

Exit:

    DPS_DBGPRINT("Exiting %s on error\n", __FUNCTION__);

    WSACloseEvent(event[0]);
    WSACloseEvent(event[1]);

    return -1;
}


DPS_Status DPS_NetworkInit(DPS_Node* node)
{
    DPS_Status status = DPS_OK;
    WSADATA wsaData;
    WORD version = MAKEWORD(2, 0);
    int ret = WSAStartup(version, &wsaData);
    if (ret) {
        DPS_DBGPRINT("WSAStartup failed with error: %d\n", ret);
        status = DPS_ERR_NETWORK;
    }
    memset(&netContext, 0, sizeof(netContext));
    node->network = &netContext;
    return status;
}

void DPS_NetworkTerminate(DPS_Node* node)
{
    node->network = NULL;
    WSACleanup();
}

static SOCKET BindSock(int family)
{
    int ret = 0;
    SOCKET sock;
    struct sockaddr_storage storage;
    socklen_t len = sizeof(storage);

    sock = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        DPS_DBGPRINT("%s: WSASocketW() failed. WSAGetLastError()=0x%x\n", __FUNCTION__, WSAGetLastError());
    } else {
        ULONG yes = 1;
        /* Set SO_REUSEADDR on the socket. */
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof yes);
        if (ret == SOCKET_ERROR) {
            DPS_DBGPRINT("%s: setsockopt SO_REUSEADDR failed. WSAGetLastError()=0x%x\n", __FUNCTION__, WSAGetLastError());
        }
        memset(&storage, 0, len);
        if (family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)&storage;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(COAP_UDP_PORT);
            sin->sin_addr.s_addr = INADDR_ANY;
        } else {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)&storage;
            sin->sin6_family = AF_INET6;
            sin->sin6_port = htons(COAP_UDP_PORT);
            sin->sin6_addr = in6addr_any;
        }
        ret = bind(sock, (struct sockaddr*)&storage, len);
        if (ret == SOCKET_ERROR) {
            DPS_DBGPRINT("%s: bind() %s failed. WSAGetLastError()=0x%x\n", __FUNCTION__, family == AF_INET ? "IPv4" : "IPv6", WSAGetLastError());
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }
    return sock;
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

DPS_Status DPS_MCastStart(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Network* network = node->network;
    struct addrinfo hints;
    INT ret;
    GROUP_REQ req4;
    GROUP_REQ req6;
    PIP_ADAPTER_ADDRESSES adapterList = NULL;
    PIP_ADAPTER_ADDRESSES adapter;

    /* Bind the IPv4 and IPv6 recv sockets */
    network->mcastRecvSock[IPV4] = BindSock(AF_INET);
    network->mcastRecvSock[IPV6] = BindSock(AF_INET6);
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
        freeaddrinfo(ai);
    }
    /* Get the network interfaces and set up the multicast groups */
    adapterList = GetAdapters();
    if (!adapterList) {
        goto ErrorExit;
    }
    /* Adapters is returned as a linked list */
    for (adapter = adapterList; adapter; adapter = adapter->Next) {
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
    }
    network->mcastRecvCB = cb;
    free(adapterList);
    adapterList = NULL;

    /* Start the multicast recv thread */
    recvThreadHandle = CreateThread(NULL, 0, MCastRecvThread, node, 0, NULL);
    if (recvThreadHandle == NULL) {
        DPS_DBGPRINT("Failed to start multicast receive thread\n");
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
