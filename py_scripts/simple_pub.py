#!/usr/bin/python
import dps
import time

# Pre-shared keys for testing only. DO NOT USE THESE KEYS IN A REAL APPLICATION!

network_key_id = [
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
]
network_key = [
    0xcd,0xfe,0x31,0x59,0x70,0x5f,0xe4,0xc8,0xcb,0x40,0xac,0x69,0x9c,0x06,0x3a,0x1d
]
key_id = [
    [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2],
    [0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc],
]
key_data = [
    [0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10],
    [0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98],
]
ca = """-----BEGIN CERTIFICATE-----\r
MIIB1jCCAX2gAwIBAgIJALRXvI4W22jOMAoGCCqGSM49BAMCMEgxCzAJBgNVBAYT\r
AlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxDDAKBgNVBAoMA0RQUzEUMBIGA1UE\r
AwwLRFBTIFRlc3QgQ0EwHhcNMTgwMTA1MTc0MjAwWhcNMjgwMTAzMTc0MjAwWjBI\r
MQswCQYDVQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANE\r
UFMxFDASBgNVBAMMC0RQUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\r
QgAE1c0x+gXvDcKjqOPOzGOu+C4u3YGvPoex0ZDqpcvp0q/S3cvUmzoZp7Q+yZpu\r
2uR37hWCi8/87+JlYBO5Pqb6E6NQME4wHQYDVR0OBBYEFFTsOv15WFWhHgST28JS\r
SbbnUdJ7MB8GA1UdIwQYMBaAFFTsOv15WFWhHgST28JSSbbnUdJ7MAwGA1UdEwQF\r
MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgR4LKUEdYIaMMzBTDXfI2E/PZ2xKfBpei\r
Wu+a8mdVTg4CIHXjJbMxosMAruzdFtf9Ik0bKfhFoXfr6XfFVsVxcU9l\r
-----END CERTIFICATE-----\r
"""
publisher_id = "DPS Test Publisher"
publisher_cert = """-----BEGIN CERTIFICATE-----\r
MIIBiDCCAS0CCQCzbzjgbS2buTAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r
MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r
UyBUZXN0IENBMB4XDTE4MDEwNTE3NDIyNVoXDTI4MDEwMzE3NDIyNVowTzELMAkG\r
A1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEMMAoGA1UECgwDRFBTMRsw\r
GQYDVQQDDBJEUFMgVGVzdCBQdWJsaXNoZXIwWTATBgcqhkjOPQIBBggqhkjOPQMB\r
BwNCAAT9zFcF+A/Hp8mD4DZSUrbmbyQlj81LjGm7o7IBqF4mjlV7sgNtyAFvQYI7\r
3BJYbcR15byhqNYT7oM6i4WvPCH0MAoGCCqGSM49BAMCA0kAMEYCIQCX7IHcB54O\r
VBD7MQwf6aoKDHrLBA2oAk60Stxcfx5RdAIhAL3Dwkrz9BTjK7YbUPScMBUPO/8k\r
68kLmXJncgz0HCAl\r
-----END CERTIFICATE-----\r
"""
publisher_private_key = """-----BEGIN EC PRIVATE KEY-----\r
Proc-Type: 4,ENCRYPTED\r
DEK-Info: AES-256-CBC,1015081BA68E2CFF939DD7F15415B0A8\r
\r
Fqu58/SuC8tFL5gpje6JI+Raq9DiCo/xWu32RzHastU20xie/8xO5ts+aLXQHPO+\r
y/mogXxVnkfLBelgz3BhxitMOM2jEm3P8BwXzDWvm3BK5AneUaQMROHTMzU/pDlD\r
DFcbIyQqLTFp0QLrvzplZWsFBAKXLs2bxcuyqRv4+h4=\r
-----END EC PRIVATE KEY-----\r
"""
publisher_password = "DPS Test Publisher"
subscriber_id = "DPS Test Subscriber1"
subscriber_cert = """-----BEGIN CERTIFICATE-----\r
MIIBczCCARgCCQCzbzjgbS2b2jAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r
MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r
UyBUZXN0IENBMB4XDTE4MDExOTIyMzY1OFoXDTI4MDExNzIyMzY1OFowOjELMAkG\r
A1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEdMBsGA1UEAwwURFBTIFRlc3QgU3Vic2Ny\r
aWJlcjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7BByLwNDLOMgMN/eNc1dO\r
DdrF4ORuD23+6P69ZebAacoitDE1f8HXrum5JlIPeXPsI5W/uficO5ntaJbtuhF1\r
MAoGCCqGSM49BAMCA0kAMEYCIQDD30ZrLlGHqftQytzjqhRs78qvnkh1iDWuo6e0\r
Ypr3yQIhAKtYWwXfJMWj9f/47NXqwDVZE26dXIjIaprEShLk8seJ\r
-----END CERTIFICATE-----\r
"""
subscriber_private_key = """-----BEGIN EC PRIVATE KEY-----\r
Proc-Type: 4,ENCRYPTED\r
DEK-Info: AES-256-CBC,FEA9341014E72E83E7E124E96C6688B2\r
\r
0Wn5jL+5QgOPmYxXyGPRO1YpuZ38vOvt+PsMb//a8Ui32NqG5+GWqCut4z11vqRF\r
O/eWA9g3ldNU5kupHa/ecSOnIY6+qXlLGISyQKRrtaf2mQPcuNf7KGrzNRziY17e\r
ZVk8AnM9vLERm7NXSgz+oh7liNW4az5dqMXTSdXsT3U=\r
-----END EC PRIVATE KEY-----\r
"""
subscriber_password = "DPS Test Subscriber1"

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-x", "--encryption", type=int, choices=[0,1,2], default=1,
                    help="Disable (0) or enable symmetric (1) or asymmetric(2) encryption. Default is symmetric encryption enabled.")
args = parser.parse_args()

key_store = dps.create_memory_key_store()
dps.set_network_key(key_store, network_key_id, network_key)
if args.encryption == 0:
    node_id = None
    pub_key_id = None
elif args.encryption == 1:
    for i in xrange(len(key_id)):
        dps.set_content_key(key_store, key_id[i], key_data[i])
    node_id = None
    pub_key_id = key_id[0]
elif args.encryption == 2:
    dps.set_trusted_ca(key_store, ca)
    dps.set_certificate(key_store, publisher_cert, publisher_private_key, publisher_password)
    dps.set_certificate(key_store, subscriber_cert)
    node_id = publisher_id
    pub_key_id = subscriber_id

def on_ack(pub, payload):
    print "Ack for pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
    print "    %s" % (payload)

# Enable or disable (default) DPS debug output
dps.cvar.debug = False

node = dps.create_node("/", dps.memory_key_store_handle(key_store), node_id)
permission_store = dps.create_memory_permission_store()
dps.set_permission(permission_store, None, None, dps.PERM_PUB | dps.PERM_SUB | dps.PERM_ACK)
dps.set_permission_store(node, dps.memory_permission_store_handle(permission_store))
dps.start_node(node, dps.MCAST_PUB_ENABLE_SEND, 0)
pub = dps.create_publication(node)

dps.init_publication(pub, ['a/b/c'], False, None, on_ack)
dps.publication_add_key_id(pub, pub_key_id)
dps.publish(pub, "hello")
print "Pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
time.sleep(0.1)
dps.publish(pub, "world")
print "Pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
time.sleep(0.1)

dps.destroy_publication(pub)
dps.destroy_node(node)
dps.destroy_memory_key_store(key_store)
