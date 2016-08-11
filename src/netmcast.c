#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps_dbg.h>
#include <dps.h>
#include <coap.h>
#include <network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_OFF);


#define USE_IPV4       0x10
#define USE_IPV6       0x01

struct _DPS_MulticastReceiver {
    uint8_t ipVersions;
    uv_udp_t udpRx;
    DPS_Node* node;
    void* context;
    DPS_OnReceive cb;
};

typedef struct {
    uv_udp_t udp;
    int family;
    uint8_t addr6[16];
} TxSocket;

#define MAX_BUFS  3

struct _DPS_MulticastSender {
    uint8_t ipVersions;
    TxSocket* udpTx; /* Array of Tx sockets - one per interface */
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
    buf->len = suggestedSize;
    buf->base = malloc(buf->len);
}

static void OnMcastRx(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    DPS_MulticastReceiver* receiver = (DPS_MulticastReceiver*)handle->data;

    DPS_DBGPRINT("OnMcastRx\n");
    if (nread < 0) {
        DPS_ERRPRINT("Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*)handle, NULL);
        free(buf->base);
        return;
    }
    if (addr) {
        DPS_DBGPRINT("Received buffer of size %ld from %s\n", nread, DPS_NetAddrText(addr));
    }
    receiver->cb(receiver->node, addr, (uint8_t*)buf->base, nread);
    free(buf->base);
}

static DPS_Status MulticastRxInit(DPS_MulticastReceiver* receiver)
{
    int ret;
    static struct sockaddr_in6 recv_addr;
    uv_loop_t* uv = DPS_GetLoop(receiver->node);
    uv_interface_address_t* ifsAddrs;
    int numIfs;
    int i;

    DPS_DBGPRINT("MulticastRxInit\n");

    ret = uv_ip6_addr("::", COAP_UDP_PORT, &recv_addr);
    assert(ret == 0);

    /*
     * Initialize udp multicast receive on the site local and link local IPv6 addresses
     */
    ret = uv_udp_init(uv, &receiver->udpRx);
    assert(ret == 0);
    ret = uv_udp_bind(&receiver->udpRx, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
    if (ret) {
        return DPS_ERR_NETWORK;
    }

    DPS_DBGPRINT("Binding UDP port %i\n", COAP_UDP_PORT);

    uv_interface_addresses(&ifsAddrs, &numIfs);
    for (i = 0; i < numIfs; ++i) {
        uv_interface_address_t* ifn = &ifsAddrs[i];
        char addr[INET6_ADDRSTRLEN];
        /*
         * Filter out interfaces we are not interested in
         */
        if (!UseInterface(receiver->ipVersions, ifn)) {
            continue;
        }
        if (ifn->address.address4.sin_family == AF_INET6) {
            ret = uv_ip6_name((struct sockaddr_in6*)&ifn->address, addr, sizeof(addr));
            assert(ret == 0);
            DPS_DBGPRINT("Joining IPv6 interface %s [%s]\n", ifn->name, addr);
            ret = uv_udp_set_membership(&receiver->udpRx, COAP_MCAST_ALL_NODES_LINK_LOCAL_6, addr, UV_JOIN_GROUP); 
        } else {
            ret = uv_ip4_name((struct sockaddr_in*)&ifn->address, addr, sizeof(addr));
            assert(ret == 0);
            DPS_DBGPRINT("Joining IPv4 interface %s [%s]\n", ifn->name, addr);
            ret = uv_udp_set_membership(&receiver->udpRx, COAP_MCAST_ALL_NODES_LINK_LOCAL_4, addr, UV_JOIN_GROUP); 
        }
        if (ret) {
            DPS_ERRPRINT("Join group failed: %s\n", uv_err_name(ret));
        }
    }
    uv_free_interface_addresses(ifsAddrs, numIfs);

    /*
     * Store pointer back to the receiver struct so it is available in the receive callback
     */
    receiver->udpRx.data = receiver;
    /*
     * Start listening for data
     */
    ret = uv_udp_recv_start(&receiver->udpRx, AllocBuffer, OnMcastRx);
    assert(ret == 0);

    return DPS_OK;
}

DPS_MulticastReceiver* DPS_MulticastStartReceive(DPS_Node* node, DPS_OnReceive cb)
{
    DPS_Status ret;
    DPS_MulticastReceiver* receiver = malloc(sizeof(DPS_MulticastReceiver));

    if (!receiver) {
        return NULL;
    }
    memset(receiver, 0, sizeof(*receiver));
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

static void RxCloseCB(uv_handle_t* handle)
{
    DPS_MulticastReceiver* receiver = (DPS_MulticastReceiver*)handle->data;
    free(receiver);
}

void DPS_MulticastStopReceive(DPS_MulticastReceiver* receiver)
{
    uv_close((uv_handle_t*)&receiver->udpRx, RxCloseCB);
}

/*****************************************************
 * Send path
 ****************************************************/

/*
 * Given an IPv4 interface lookup the corresponding IPv6 entry
 */
static uv_interface_address_t* GetIP6Interface(uv_interface_address_t* ifList, int numIfs, uv_interface_address_t* if4)
{
    while (numIfs--) {
        if (ifList != if4 && memcmp(&ifList->phys_addr, &if4->phys_addr, sizeof(if4->phys_addr)) == 0) {
            return ifList;
        }
        ++ifList;
    }
    return NULL;
}

static DPS_Status MulticastTxInit(DPS_MulticastSender* sender)
{
    int ret;
    struct sockaddr_in6 send_addr;
    uv_loop_t* uv = DPS_GetLoop(sender->node);
    uv_interface_address_t* ifsAddrs;
    TxSocket* sock;
    int numIfs;
    int i;

    DPS_DBGPRINT("MulticastTxInit\n");

    ret = uv_ip6_addr("::", 0, &send_addr);
    assert(ret == 0);

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
    sender->udpTx = sock = malloc(sizeof(TxSocket) * sender->numTx);
    /*
     * Initialize a socket per interface
     */
    for (i = 0; i < numIfs; ++i) {
        char ifaddr[INET6_ADDRSTRLEN + 32];
        uv_interface_address_t* ifn = &ifsAddrs[i];
        if (!UseInterface(sender->ipVersions, ifn)) {
            continue;
        }
        /*
         * Initialize udp Tx socket 
         */
        ret = uv_udp_init(uv, &sock->udp);
        assert(ret == 0);
        ret = uv_udp_bind(&sock->udp, (const struct sockaddr *)&send_addr, 0);
        assert(ret == 0);
        /*
         * Store pointer back to the sender struct
         */
        sock->udp.data = sender;
        sock->family = ifn->address.address4.sin_family;
        if (sock->family == AF_INET6) {
            /*
             * Copy the interface address into the TxSock struct we will need it later
             */
            memcpy(&sock->addr6, &ifn->address.address6.sin6_addr, 16);
            /*
             * Append interface name to the interface address for IPv6
             */
            uv_ip6_name(&ifn->address.address6, ifaddr, sizeof(ifaddr));
            strncat(ifaddr, "%", sizeof(ifaddr));
            strncat(ifaddr, ifn->name, sizeof(ifaddr));
        } else {
            /*
             * We need the IPv6 address from this interface
             */
            uv_interface_address_t* ifn6 = GetIP6Interface(ifsAddrs, numIfs, ifn);
            if (!ifn6) {
                DPS_ERRPRINT("No IP6 address for this interface: %s\n", ifn->name);
                continue;
            }
            memcpy(sock->addr6, &ifn6->address.address6.sin6_addr, 16);
            /*
             * Just the address for IPV4
             */
            uv_ip4_name(&ifn->address.address4, ifaddr, sizeof(ifaddr));
        }
        DPS_DBGPRINT("Setting interface %s [%s]\n", ifn->name, ifaddr);
        ret = uv_udp_set_multicast_interface(&sock->udp, ifaddr);
        if (ret) {
            DPS_ERRPRINT("Failed to set interface: %s\n", uv_err_name(ret));
            continue;
        }
        ++sock;
    }
    return DPS_OK;
}

DPS_MulticastSender* DPS_MulticastStartSend(DPS_Node* node)
{
    DPS_Status ret;
    DPS_MulticastSender* sender = malloc(sizeof(DPS_MulticastSender));

    if (!sender) {
        return NULL;
    }
    memset(sender, 0, sizeof(*sender));
    sender->ipVersions = USE_IPV6 | USE_IPV4;
    sender->node = node;

    ret = MulticastTxInit(sender);
    if (ret != DPS_OK) {
        free(sender);
        return NULL;
    }
    return sender;
}

static void TxCloseCB(uv_handle_t* handle)
{
    DPS_MulticastSender* sender = (DPS_MulticastSender*)handle->data;
    if (--sender->numTx == 0) {
        free(sender);
    }
}

void DPS_MulticastStopSend(DPS_MulticastSender* sender)
{
    int i;
    int numTx = sender->numTx;

    for (i = 0; i < numTx; ++i) {
        uv_close((uv_handle_t*)&sender->udpTx[i].udp, TxCloseCB);
    }
}

DPS_Status DPS_MulticastSend(DPS_MulticastSender* sender, uv_buf_t* bufs, size_t numBufs)
{
    size_t sent = 0;
    int i;
    int ret;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;

    ret = uv_ip6_addr(COAP_MCAST_ALL_NODES_LINK_LOCAL_6, COAP_UDP_PORT, &addr6);
    assert(ret == 0);

    ret = uv_ip4_addr(COAP_MCAST_ALL_NODES_LINK_LOCAL_4, COAP_UDP_PORT, &addr4);
    assert(ret == 0);

    /*
     * Send on each interface
     */
    for (i = 0; i < sender->numTx; ++i) {
        struct sockaddr* addr = (sender->udpTx[i].family == AF_INET6) ? (struct sockaddr*)&addr6 : (struct sockaddr*)&addr4;
        /*
         * Synchronous send
         */
        ret = uv_udp_try_send(&sender->udpTx[i].udp, bufs, numBufs, addr);
        if (ret < 0) {
            DPS_ERRPRINT("uv_udp_try_send to %s failed: %s\n", DPS_NetAddrText(addr), uv_err_name(ret));
        } else {
            sent += ret;
            DPS_DBGPRINT("Sent %d bytes to %s\n", ret, DPS_NetAddrText(addr));
        }
    }
    /*
     * We expect to have sent something
     */
    if (!sent) {
        return DPS_ERR_NETWORK;
    } else {
        return DPS_OK;
    }
}
