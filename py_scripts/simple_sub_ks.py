#!/usr/bin/python
import codecs
import dps
import os
import sys
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# Pre-shared keys for testing only. DO NOT USE THESE KEYS IN A REAL APPLICATION!
network_key_id = [
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
]
network_key = [
    0x11,0x21,0xbb,0xf4,0x9f,0x5e,0xe5,0x5a,0x11,0x86,0x47,0xe6,0x3d,0xc6,0x59,0xa4,
    0xc3,0x1f,0x16,0x56,0x7f,0x1f,0xb8,0x4d,0xe1,0x09,0x28,0x26,0xd5,0xc0,0xf1,0x34
]
key_id = [
    [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2],
    [0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc],
]
key_data = [
    [0xf6,0xeb,0xcb,0xa4,0x25,0xdb,0x3b,0x7e,0x73,0x03,0xe6,0x9c,0x60,0x35,0xae,0x11,
     0xae,0x40,0x0b,0x84,0xf0,0x03,0xcc,0xf9,0xce,0x5c,0x5f,0xd0,0xae,0x51,0x0a,0xcc],
    [0x2a,0x93,0xff,0x6d,0x96,0x7e,0xb3,0x20,0x85,0x80,0x0e,0x21,0xb0,0x7f,0xa7,0xbe,
     0x3f,0x53,0x68,0x57,0xf9,0x3c,0x7a,0x41,0x59,0xab,0x22,0x2c,0xf8,0xcf,0x08,0x21]
]
ca = """-----BEGIN CERTIFICATE-----\r
MIICJjCCAYegAwIBAgIJAOtGcTaglPb0MAoGCCqGSM49BAMCMCoxCzAJBgNVBAYT\r
AlVTMQwwCgYDVQQKDANEUFMxDTALBgNVBAMMBHJvb3QwHhcNMTgwMzAxMTgxNDMy\r
WhcNMjgwMjI3MTgxNDMyWjAqMQswCQYDVQQGEwJVUzEMMAoGA1UECgwDRFBTMQ0w\r
CwYDVQQDDARyb290MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLlFmM8e0WHRE\r
KF3XQBUihJJ2vQepy40aa3rRsEElQHxSu5GFOvV/FZrywrwAthiTwtF999uxgjgD\r
0nAHCWMJvVYARljnDm1+CpZFSTBeJsw0S7s4nA4s3bm07L3neSsMIADa+tUbIhMY\r
G5OWJ645pcMm4pc/Sv8yZoxffaJu6BUSPsejUzBRMB0GA1UdDgQWBBR15MMwK1i9\r
T9Ux9ZkP+W2eZ77RODAfBgNVHSMEGDAWgBR15MMwK1i9T9Ux9ZkP+W2eZ77RODAP\r
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJCALVJ7AvWFEmn7EgS\r
XSd432PYQLLhwVlmyMiAkiv8A93pQeofJBbnZHjJOQH3tttBhmLIMZy/npjkPqUJ\r
riJlVcRKAkIBIhqssJD6XDlyV42a989vmuB52FGsBayiIkoJgzeoTZLLoGFtddpg\r
KNuru7XZOpdiszeXTDSPY7gmvYZGhLr58ng=\r
-----END CERTIFICATE-----\r
"""
publisher_id = "DPS Test Publisher"
publisher_cert = """-----BEGIN CERTIFICATE-----\r
MIIB2jCCATsCCQDtkL14u3NJRDAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r
MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r
MDIyNzE4MTQzMlowODELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEbMBkGA1UE\r
AwwSRFBTIFRlc3QgUHVibGlzaGVyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB\r
igbpvXYHms+7wTa1BcAf3PQF3/6R/J92HcbiPtPGVNlPYdpCnyYEF7DoNvgI/Iag\r
EqUjryMWoxwi+KghG1BwA2MAKhn/ta4TAXfASPr9gzYK5g+pKFnOXqc4sWut/o8D\r
se6LU2D3PsQBs5/kCkbjz1/sKQVbDJGT5eTHQvC5nxjToZcwCgYIKoZIzj0EAwQD\r
gYwAMIGIAkIBIEo4NfnSh60U4srn2iSR/u5VFHi4Yy3PjlKlkmRDo+ClPVHPOK7y\r
8/82J1qlTw5GSR0snR4R5663D2s3w2e9fIwCQgCp3K8Y7fTPdpwOy91clBr3OFHK\r
sMt3kjq1vrcbVzZy50hGyGxjUqZHUi87/KuhkcMKSqDC6U7jEiEpv/WNH/VrZQ==\r
-----END CERTIFICATE-----\r
"""
publisher_private_key = """-----BEGIN EC PRIVATE KEY-----\r
Proc-Type: 4,ENCRYPTED\r
DEK-Info: AES-256-CBC,F0004AF499EA7B8A7252B286E3274508\r
\r
M5Du62n9VNOQjomIiToNODHeUexM6/kd/BJv5htLIKK+IuWhbz7uKiDa1ULrxz5x\r
KVEh6b0h3WjQ5Z+tlHGGedD4uarwWcUDaw9j2kTpaN33HuCmQAEgH7Lqtq4BnI4S\r
7FDtpoXtMOWGBs/AhQlUXQE0lFENacZ3PLkbafHVzcm19hWZk19ANpZOPbRNgMdQ\r
vPIAyubRAwG+M+wtCxoG9kvwA2TpriwTPb3HaTtefXcaxM8ijS/VQa5mFjphSeUn\r
BcrDGodlTMw9klV0eJpmDKUrpiXqExhzCsS33jK9YuM=\r
-----END EC PRIVATE KEY-----\r
"""
publisher_password = "DPS Test Publisher"
subscriber_id = "DPS Test Subscriber"
subscriber_cert = """-----BEGIN CERTIFICATE-----\r
MIIB2jCCATwCCQDtkL14u3NJRTAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r
MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r
MDIyNzE4MTQzMlowOTELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEcMBoGA1UE\r
AwwTRFBTIFRlc3QgU3Vic2NyaWJlcjCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE\r
AdPlr3YCutvRP0agz6KRmVVY4HuzS5zmEaBzkTCSWFkhugDgwmMgszDCAD5maqe5\r
nAHammIc/MSw1UK+JFLFzSffAB48lbymUgTtE41sXWx82gc6vwvU25DqnNxHgS0L\r
K0bVQweaXa4toICC3SLZD0iRDI1jUqZPwDCkbpF9LyDDa181MAoGCCqGSM49BAME\r
A4GLADCBhwJBP7gFuL3dePSkYG4LoBg1atH6+2xfJWg51ZV8diRXWIgRlC5u3kCQ\r
R+AJhf+Slik1tMQePTB5OojwrRYjw40iEDoCQgE6rg0vAE2AZVLYfVsz01we+Rov\r
L8bFbjmY7xtqNCqRgCP7Nb/DLED8ahqo+uI7tPx5EqxDWj0FdxewZnbnBorBug==\r
-----END CERTIFICATE-----\r
"""
subscriber_private_key = """-----BEGIN EC PRIVATE KEY-----\r
Proc-Type: 4,ENCRYPTED\r
DEK-Info: AES-256-CBC,65E2556079AC9649D58B8CC72AE4A43E\r
\r
qWEHBFDO16P65LBjQecIrcql5bWuUx2SO87Qgllm576xolusU+iTExRVENjtO3Nl\r
Vil2EqdMX2KHdv9p282lW1Drl069SesP69LiOo0sMYJefWJZRSnbRL7e7tDTXuUz\r
p038ythZg7Ho6UggO6cvy08JomqMuJtwpJ6RTTFAsQMsEqCF8m0e26EdxrFUpkrM\r
imwGuJ3hGzJKTZYaqK8i17LK+m4W0FzXETXp+qDyp9LBuZTqBISJ7MH+LOnY4neZ\r
a/F20EFCFwL47sfQlZMsOYHw140IS2+YOyzOD051Gbw=\r
-----END EC PRIVATE KEY-----\r
"""
subscriber_password = "DPS Test Subscriber"

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action='store_true',
                    help="Enable debug ouput if built for debug.")
parser.add_argument("-x", "--encryption", type=int, choices=[0,1,2], default=1,
                    help="Disable (0) or enable symmetric (1) or asymmetric(2) encryption. Default is symmetric encryption enabled.")
args = parser.parse_args()
dps.cvar.debug = args.debug

def compare(a, b):
    if a == None or b == None:
        return False
    elif len(a) != len(b):
        return False
    elif type(a) == type(b):
        return a == b
    elif type(b) is bytearray:
        if type(a) is str:
            return bytearray(a, "utf-8") == b
        else:
            return bytearray(a) == b
    elif type(b) is str:
        return "".join(str(c) for c in a) == b
    else:
        return False
def int_to_bytes(b, n):
    s = "%x" % b
    if len(s) & 1:
        s = "0" + s
    while len(s) != (n * 2):
        s = "0" + s
    return codecs.decode(s, "hex")
def on_key_and_id(request):
    return dps.set_key_and_id(request, dps.KeySymmetric(network_key), network_key_id);
def on_key(request, id):
    for i in range(0, len(key_id)):
        if compare(key_id[i], id):
            return dps.set_key(request, dps.KeySymmetric(key_data[i]))
    if compare(network_key_id, id):
        return dps.set_key(request, dps.KeySymmetric(network_key))
    if compare(publisher_id, id):
        return dps.set_key(request, dps.KeyCert(publisher_cert));
    if compare(subscriber_id, id):
        return dps.set_key(request, dps.KeyCert(subscriber_cert, subscriber_private_key, subscriber_password));
    return dps.ERR_MISSING
def on_ephemeral_key(request, key):
    if key.type == dps.KEY_SYMMETRIC:
        return dps.set_key(request, dps.KeySymmetric(os.urandom(32)))
    elif key.type == dps.KEY_EC:
        if key.curve == dps.EC_CURVE_P384:
            curve = ec.SECP384R1()
            n = 48
        elif key.curve == dps.EC_CURVE_P521:
            curve = ec.SECP521R1()
            n = 66
        k = ec.generate_private_key(curve, default_backend())
        x = int_to_bytes(k.public_key().public_numbers().x, n)
        y = int_to_bytes(k.public_key().public_numbers().y, n)
        d = int_to_bytes(k.private_numbers().private_value, n)
        return dps.set_key(request, dps.KeyEC(key.curve, x, y, d))
    else:
        return dps.ERR_MISSING
def on_ca(request):
    return dps.set_ca(request, ca)

if args.encryption == 0:
    key_store = dps.create_key_store(on_key_and_id, on_key, on_ephemeral_key, None)
    node_id = None
elif args.encryption == 1:
    key_store = dps.create_key_store(on_key_and_id, on_key, on_ephemeral_key, None)
    node_id = None
elif args.encryption == 2:
    key_store = dps.create_key_store(on_key_and_id, on_key, on_ephemeral_key, on_ca)
    node_id = subscriber_id

def on_pub(sub, pub, payload):
    print("Pub %s(%d) matches:" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub)))
    print("  pub " + " | ".join(dps.publication_get_topics(pub)))
    print("  sub " + " | ".join(dps.subscription_get_topics(sub)))
    print(payload.tobytes())
    if dps.publication_is_ack_requested(pub):
        ack_msg = "This is an ACK from %s" % (dps.get_listen_address(dps.publication_get_node(pub)))
        print("Sending ack for pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub)))
        print("    %s" % (ack_msg))
        dps.ack_publication(pub, ack_msg);

node = dps.create_node("/", key_store, node_id)
dps.start_node(node, dps.MCAST_PUB_ENABLE_RECV, None)
print("Subscriber is listening on %s" % (dps.get_listen_address(node)))
sub = dps.create_subscription(node, ['a/b/c']);
dps.subscribe(sub, on_pub)

if not sys.flags.interactive:
    while True:
        time.sleep(1)
