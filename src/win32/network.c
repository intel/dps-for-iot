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

struct _DPS_Network {
    SOCKET mcastRecvSock4;
    SOCKET mcastRecvSock6;
    DPS_OnReceive mcastRecvCB;
    DPS_OnReceive recvCB;
};

static DPS_Network netContext;


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

    sock = socket(family, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        DPS_DBGPRINT("%s: socket failed. WSAGetLastError()=0x%x\n", __FUNCTION__, WSAGetLastError());
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
            sin->sin_port = htons(0);
            sin->sin_addr.s_addr = INADDR_ANY;
        } else {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)&storage;
            sin->sin6_family = AF_INET6;
            sin->sin6_port = htons(0);
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
    network->mcastRecvSock4 = BindSock(AF_INET);
    network->mcastRecvSock6 = BindSock(AF_INET6);
    /* OK if we have at least one network family */
    if (network->mcastRecvSock4 == INVALID_SOCKET && network->mcastRecvSock6 == INVALID_SOCKET) {
        return DPS_ERR_NETWORK;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    /* Configure the IPv4 request */
    if (network->mcastRecvSock4 != INVALID_SOCKET) {
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
    if (network->mcastRecvSock6 != INVALID_SOCKET) {
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
        if (network->mcastRecvSock4 != INVALID_SOCKET) {
            req4.gr_interface = adapter->IfIndex;
            ret = setsockopt(network->mcastRecvSock4, IPPROTO_IP, MCAST_JOIN_GROUP, (char*)&req4, sizeof(req4));
            if (ret == SOCKET_ERROR) {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv4 failed (%d)\n", WSAGetLastError());
            } else {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv4 sucessful\n");
            }
        } 
        if (network->mcastRecvSock6 != INVALID_SOCKET) {
            req6.gr_interface = adapter->IfIndex;
            ret = setsockopt(network->mcastRecvSock6, IPPROTO_IPV6, MCAST_JOIN_GROUP, (char*)&req6, sizeof(req6));
            if (ret == SOCKET_ERROR) {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv6 failed (%d)\n", WSAGetLastError());
            } else {
                DPS_DBGPRINT("MCAST_JOIN_GOUP IPv6 sucessful\n");
            }
        } 
    }
    network->mcastRecvCB = cb;
    free(adapterList);
    return DPS_OK;

ErrorExit:

    if (adapterList) {
        free(adapterList);
    }
    closesocket(node->network->mcastRecvSock4);
    closesocket(node->network->mcastRecvSock6);

    return DPS_ERR_NETWORK;

}
