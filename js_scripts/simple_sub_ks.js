"use strict";
var dps = require("dps");
var crypto = require("crypto");

(function () {
    /* Pre-shared keys for testing only. DO NOT USE THESE KEYS IN A REAL APPLICATION! */
    var networkKeyID = [
        0x4c, 0xfc, 0x6b, 0x75, 0x0f, 0x80, 0x95, 0xb3, 0x6c, 0xb7, 0xc1, 0x2f, 0x65, 0x2d, 0x38, 0x26
    ];
    var networkKey = [
        0xcd, 0xfe, 0x31, 0x59, 0x70, 0x5f, 0xe4, 0xc8, 0xcb, 0x40, 0xac, 0x69, 0x9c, 0x06, 0x3a, 0x1d
    ];
    var keyID = [
        [0xed, 0x54, 0x14, 0xa8, 0x5c, 0x4d, 0x4d, 0x15, 0xb6, 0x9f, 0x0e, 0x99, 0x8a, 0xb1, 0x71, 0xf2],
        [0x53, 0x4d, 0x2a, 0x4b, 0x98, 0x76, 0x1f, 0x25, 0x6b, 0x78, 0x3c, 0xc2, 0xf8, 0x12, 0x90, 0xcc]
    ];
    var keyData = [
        [0x77, 0x58, 0x22, 0xfc, 0x3d, 0xef, 0x48, 0x88, 0x91, 0x25, 0x78, 0xd0, 0xe2, 0x74, 0x5c, 0x10],
        [0x39, 0x12, 0x3e, 0x7f, 0x21, 0xbc, 0xa3, 0x26, 0x4e, 0x6f, 0x3a, 0x21, 0xa4, 0xf1, 0xb5, 0x98]
    ];
    var ca = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIB1jCCAX2gAwIBAgIJALRXvI4W22jOMAoGCCqGSM49BAMCMEgxCzAJBgNVBAYT\r\n" +
        "AlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxDDAKBgNVBAoMA0RQUzEUMBIGA1UE\r\n" +
        "AwwLRFBTIFRlc3QgQ0EwHhcNMTgwMTA1MTc0MjAwWhcNMjgwMTAzMTc0MjAwWjBI\r\n" +
        "MQswCQYDVQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANE\r\n" +
        "UFMxFDASBgNVBAMMC0RQUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\r\n" +
        "QgAE1c0x+gXvDcKjqOPOzGOu+C4u3YGvPoex0ZDqpcvp0q/S3cvUmzoZp7Q+yZpu\r\n" +
        "2uR37hWCi8/87+JlYBO5Pqb6E6NQME4wHQYDVR0OBBYEFFTsOv15WFWhHgST28JS\r\n" +
        "SbbnUdJ7MB8GA1UdIwQYMBaAFFTsOv15WFWhHgST28JSSbbnUdJ7MAwGA1UdEwQF\r\n" +
        "MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgR4LKUEdYIaMMzBTDXfI2E/PZ2xKfBpei\r\n" +
        "Wu+a8mdVTg4CIHXjJbMxosMAruzdFtf9Ik0bKfhFoXfr6XfFVsVxcU9l\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var publisherId = "DPS Test Publisher";
    var publisherCert = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIBiDCCAS0CCQCzbzjgbS2buTAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n" +
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n" +
        "UyBUZXN0IENBMB4XDTE4MDEwNTE3NDIyNVoXDTI4MDEwMzE3NDIyNVowTzELMAkG\r\n" +
        "A1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEMMAoGA1UECgwDRFBTMRsw\r\n" +
        "GQYDVQQDDBJEUFMgVGVzdCBQdWJsaXNoZXIwWTATBgcqhkjOPQIBBggqhkjOPQMB\r\n" +
        "BwNCAAT9zFcF+A/Hp8mD4DZSUrbmbyQlj81LjGm7o7IBqF4mjlV7sgNtyAFvQYI7\r\n" +
        "3BJYbcR15byhqNYT7oM6i4WvPCH0MAoGCCqGSM49BAMCA0kAMEYCIQCX7IHcB54O\r\n" +
        "VBD7MQwf6aoKDHrLBA2oAk60Stxcfx5RdAIhAL3Dwkrz9BTjK7YbUPScMBUPO/8k\r\n" +
        "68kLmXJncgz0HCAl\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var publisherPrivateKey = "-----BEGIN EC PRIVATE KEY-----\r\n" +
        "Proc-Type: 4,ENCRYPTED\r\n" +
        "DEK-Info: AES-256-CBC,1015081BA68E2CFF939DD7F15415B0A8\r\n" +
        "\r\n" +
        "Fqu58/SuC8tFL5gpje6JI+Raq9DiCo/xWu32RzHastU20xie/8xO5ts+aLXQHPO+\r\n" +
        "y/mogXxVnkfLBelgz3BhxitMOM2jEm3P8BwXzDWvm3BK5AneUaQMROHTMzU/pDlD\r\n" +
        "DFcbIyQqLTFp0QLrvzplZWsFBAKXLs2bxcuyqRv4+h4=\r\n" +
        "-----END EC PRIVATE KEY-----\r\n";
    var publisherPassword = "DPS Test Publisher";
    var subscriberId = "DPS Test Subscriber";
    var subscriberCert = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIBiTCCAS4CCQCzbzjgbS2bujAKBggqhkjOPQQDAjBIMQswCQYDVQQGEwJVUzEV\r\n" +
        "MBMGA1UEBwwMRGVmYXVsdCBDaXR5MQwwCgYDVQQKDANEUFMxFDASBgNVBAMMC0RQ\r\n" +
        "UyBUZXN0IENBMB4XDTE4MDEwNTE3NDI0NloXDTI4MDEwMzE3NDI0NlowUDELMAkG\r\n" +
        "A1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEMMAoGA1UECgwDRFBTMRww\r\n" +
        "GgYDVQQDDBNEUFMgVGVzdCBTdWJzY3JpYmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0D\r\n" +
        "AQcDQgAEbrDkznbJynaPPfKnnkx14nLX782a2SiPZHYFrDseHwoLOqWe6TI2bcIm\r\n" +
        "rPEDasOnc8fywObXDwEKyRgIR1gqLDAKBggqhkjOPQQDAgNJADBGAiEAj7V5KV3y\r\n" +
        "SwVLhWGC4tey6zs7G+IQMNPQF0A/+Ic1hLICIQD7TumHocAG2SG42IE4WcwllrBG\r\n" +
        "LmXKOg4TBaBxS5GrDg==\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var subscriberPrivateKey = "-----BEGIN EC PRIVATE KEY-----\r\n" +
        "Proc-Type: 4,ENCRYPTED\r\n" +
        "DEK-Info: AES-256-CBC,7F349D976187178514F51358734287B2\r\n" +
        "\r\n" +
        "uc2MV05GoQf5WKC62U1n5dX9O11OehzpxKVKQiiMoqB+PnkyFR8+eS/CLdhtHPC9\r\n" +
        "cU6HJDaPdUFZlV0L+Dhl3L1vm0zBvRpIZUivZGzB3h6RMptvhoZ5rey1f1Kyq7oj\r\n" +
        "1rEBHuMR4LT4PCrDQ4DpvOvAiJGpPMEaEovKhy+IneQ=\r\n" +
        "-----END EC PRIVATE KEY-----\r\n";
    var subscriberPassword = "DPS Test Subscriber";
    var keyStore;
    var nodeId;
    var node;
    var sub;
    var i;
    var encryption;

    var compare = function(a, b) {
        var i;

        if (a.length != b.length) {
            return false;
        }
        if (typeof a == "string") {
            for (i = 0; i < a.length; ++i) {
                if (a.charCodeAt(i) != b[i]) {
                    return false;
                }
            }
        } else {
            for (i = 0; i < a.length; ++i) {
                if (a[i] != b[i]) {
                    return false;
                }
            }
        }
        return true;
    }
    var onKeyAndId = function(request) {
        return dps.setKeyAndId(request, new dps.KeySymmetric(networkKey), networkKeyID);
    }
    var onKey = function(request, id) {
        var i, j;

        for (i = 0; i < keyID.length; ++i) {
            if (compare(keyID[i], id)) {
                return dps.setKey(request, new dps.KeySymmetric(keyData[i]));
            }
        }
        if (compare(networkKeyID, id)) {
            return dps.setKey(request, new dps.KeySymmetric(networkKey));
        }
        if (compare(publisherId, id)) {
            return dps.setKey(request, new dps.KeyCert(publisherCert));
        }
        if (compare(subscriberId, id)) {
            return dps.setKey(request, new dps.KeyCert(subscriberCert, subscriberPrivateKey, subscriberPassword));
        }
        return dps.ERR_MISSING;
    };
    var onEphemeralKey = function(request, key) {
        var ecdh;
        var n;
        var x, y, d;

        switch (key.type) {
        case dps.KEY_SYMMETRIC:
            return dps.setKey(request, new dps.KeySymmetric(crypto.randomBytes(16)));
        case dps.KEY_EC:
            switch (key.curve) {
            case dps.EC_CURVE_P256:
                ecdh = crypto.createECDH("prime256v1");
                n = 32;
                break;
            case dps.EC_CURVE_P384:
                ecdh = crypto.createECDH("secp384r1");
                n = 48;
                break;
            case dps.EC_CURVE_P521:
                ecdh = crypto.createECDH("secp521r1");
                n = 66;
                break;
            };
            ecdh.generateKeys();
            x = ecdh.getPublicKey().slice(1, n + 1);
            y = ecdh.getPublicKey().slice(n + 1, (2 * n) + 1);
            d = ecdh.getPrivateKey();
            return dps.setKey(request, new dps.KeyEC(key.curve, x, y, d));
        default:
            return dps.ERR_MISSING;
        }
    };
    var onCA = function(request) {
        return dps.setCA(request, ca);
    };

    var onPub = function (sub, pub, payload) {
        var ackMsg;
        console.log("Pub " + dps.publicationGetUUID(pub) + "(" + dps.publicationGetSequenceNum(pub) + ") matches:");
        console.log("  pub " + dps.publicationGetTopics(pub).join(" | "));
        console.log("  sub " + dps.subscriptionGetTopics(sub).join(" | "));
        console.log(payload);
        if (dps.publicationIsAckRequested(pub)) {
            ackMsg = "This is an ACK from " + dps.getPortNumber(dps.publicationGetNode(pub));
            console.log("Sending ack for pub UUID " + dps.publicationGetUUID(pub) + "(" + dps.publicationGetSequenceNum(pub) + ")");
            console.log("    " + ackMsg);
            dps.ackPublication(pub, ackMsg);
        }
    };

    encryption = 1;
    for (i = 0; i < process.argv.length; ++i) {
        if (process.argv[i] == "-x") {
            encryption = process.argv[++i];
        } else if (process.argv[i] == "-d") {
            dps.debug = 1;
        }
    }

    if (encryption == 0) {
        keyStore = dps.createKeyStore(onKeyAndId, onKey, onEphemeralKey, null);
        nodeId = null;
    } else if (encryption == 1) {
        keyStore = dps.createKeyStore(onKeyAndId, onKey, onEphemeralKey, null);
        nodeId = null;
    } else if (encryption == 2) {
        keyStore = dps.createKeyStore(onKeyAndId, onKey, onEphemeralKey, onCA);
        nodeId = subscriberId;
    }

    node = dps.createNode("/", keyStore, nodeId);
    dps.startNode(node, dps.MCAST_PUB_ENABLE_RECV, 0);
    sub = dps.createSubscription(node, ["a/b/c"]);
    dps.subscribe(sub, onPub);
}());
