"use strict";
var dps = require("dps");
var crypto = require("crypto");

(function () {
    /* Pre-shared keys for testing only. DO NOT USE THESE KEYS IN A REAL APPLICATION! */
    var networkKeyID = [
        0x4c, 0xfc, 0x6b, 0x75, 0x0f, 0x80, 0x95, 0xb3, 0x6c, 0xb7, 0xc1, 0x2f, 0x65, 0x2d, 0x38, 0x26
    ];
    var networkKey = [
        0x11, 0x21, 0xbb, 0xf4, 0x9f, 0x5e, 0xe5, 0x5a, 0x11, 0x86, 0x47, 0xe6, 0x3d, 0xc6, 0x59, 0xa4,
        0xc3, 0x1f, 0x16, 0x56, 0x7f, 0x1f, 0xb8, 0x4d, 0xe1, 0x09, 0x28, 0x26, 0xd5, 0xc0, 0xf1, 0x34
    ];
    var keyID = [
        [0xed, 0x54, 0x14, 0xa8, 0x5c, 0x4d, 0x4d, 0x15, 0xb6, 0x9f, 0x0e, 0x99, 0x8a, 0xb1, 0x71, 0xf2],
        [0x53, 0x4d, 0x2a, 0x4b, 0x98, 0x76, 0x1f, 0x25, 0x6b, 0x78, 0x3c, 0xc2, 0xf8, 0x12, 0x90, 0xcc]
    ];
    var keyData = [
        [0xf6, 0xeb, 0xcb, 0xa4, 0x25, 0xdb, 0x3b, 0x7e, 0x73, 0x03, 0xe6, 0x9c, 0x60, 0x35, 0xae, 0x11,
         0xae, 0x40, 0x0b, 0x84, 0xf0, 0x03, 0xcc, 0xf9, 0xce, 0x5c, 0x5f, 0xd0, 0xae, 0x51, 0x0a, 0xcc],
        [0x2a, 0x93, 0xff, 0x6d, 0x96, 0x7e, 0xb3, 0x20, 0x85, 0x80, 0x0e, 0x21, 0xb0, 0x7f, 0xa7, 0xbe,
         0x3f, 0x53, 0x68, 0x57, 0xf9, 0x3c, 0x7a, 0x41, 0x59, 0xab, 0x22, 0x2c, 0xf8, 0xcf, 0x08, 0x21]
    ];
    var ca = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIICJjCCAYegAwIBAgIJAOtGcTaglPb0MAoGCCqGSM49BAMCMCoxCzAJBgNVBAYT\r\n" +
        "AlVTMQwwCgYDVQQKDANEUFMxDTALBgNVBAMMBHJvb3QwHhcNMTgwMzAxMTgxNDMy\r\n" +
        "WhcNMjgwMjI3MTgxNDMyWjAqMQswCQYDVQQGEwJVUzEMMAoGA1UECgwDRFBTMQ0w\r\n" +
        "CwYDVQQDDARyb290MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLlFmM8e0WHRE\r\n" +
        "KF3XQBUihJJ2vQepy40aa3rRsEElQHxSu5GFOvV/FZrywrwAthiTwtF999uxgjgD\r\n" +
        "0nAHCWMJvVYARljnDm1+CpZFSTBeJsw0S7s4nA4s3bm07L3neSsMIADa+tUbIhMY\r\n" +
        "G5OWJ645pcMm4pc/Sv8yZoxffaJu6BUSPsejUzBRMB0GA1UdDgQWBBR15MMwK1i9\r\n" +
        "T9Ux9ZkP+W2eZ77RODAfBgNVHSMEGDAWgBR15MMwK1i9T9Ux9ZkP+W2eZ77RODAP\r\n" +
        "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJCALVJ7AvWFEmn7EgS\r\n" +
        "XSd432PYQLLhwVlmyMiAkiv8A93pQeofJBbnZHjJOQH3tttBhmLIMZy/npjkPqUJ\r\n" +
        "riJlVcRKAkIBIhqssJD6XDlyV42a989vmuB52FGsBayiIkoJgzeoTZLLoGFtddpg\r\n" +
        "KNuru7XZOpdiszeXTDSPY7gmvYZGhLr58ng=\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var publisherId = "DPS Test Publisher";
    var publisherCert = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIB2jCCATsCCQDtkL14u3NJRDAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n" +
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r\n" +
        "MDIyNzE4MTQzMlowODELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEbMBkGA1UE\r\n" +
        "AwwSRFBTIFRlc3QgUHVibGlzaGVyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB\r\n" +
        "igbpvXYHms+7wTa1BcAf3PQF3/6R/J92HcbiPtPGVNlPYdpCnyYEF7DoNvgI/Iag\r\n" +
        "EqUjryMWoxwi+KghG1BwA2MAKhn/ta4TAXfASPr9gzYK5g+pKFnOXqc4sWut/o8D\r\n" +
        "se6LU2D3PsQBs5/kCkbjz1/sKQVbDJGT5eTHQvC5nxjToZcwCgYIKoZIzj0EAwQD\r\n" +
        "gYwAMIGIAkIBIEo4NfnSh60U4srn2iSR/u5VFHi4Yy3PjlKlkmRDo+ClPVHPOK7y\r\n" +
        "8/82J1qlTw5GSR0snR4R5663D2s3w2e9fIwCQgCp3K8Y7fTPdpwOy91clBr3OFHK\r\n" +
        "sMt3kjq1vrcbVzZy50hGyGxjUqZHUi87/KuhkcMKSqDC6U7jEiEpv/WNH/VrZQ==\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var publisherPrivateKey = "-----BEGIN EC PRIVATE KEY-----\r\n" +
        "Proc-Type: 4,ENCRYPTED\r\n" +
        "DEK-Info: AES-256-CBC,F0004AF499EA7B8A7252B286E3274508\r\n" +
        "\r\n" +
        "M5Du62n9VNOQjomIiToNODHeUexM6/kd/BJv5htLIKK+IuWhbz7uKiDa1ULrxz5x\r\n" +
        "KVEh6b0h3WjQ5Z+tlHGGedD4uarwWcUDaw9j2kTpaN33HuCmQAEgH7Lqtq4BnI4S\r\n" +
        "7FDtpoXtMOWGBs/AhQlUXQE0lFENacZ3PLkbafHVzcm19hWZk19ANpZOPbRNgMdQ\r\n" +
        "vPIAyubRAwG+M+wtCxoG9kvwA2TpriwTPb3HaTtefXcaxM8ijS/VQa5mFjphSeUn\r\n" +
        "BcrDGodlTMw9klV0eJpmDKUrpiXqExhzCsS33jK9YuM=\r\n" +
        "-----END EC PRIVATE KEY-----\r\n";
    var publisherPassword = "DPS Test Publisher";
    var subscriberId = "DPS Test Subscriber";
    var subscriberCert = "-----BEGIN CERTIFICATE-----\r\n" +
        "MIIB2jCCATwCCQDtkL14u3NJRTAKBggqhkjOPQQDBDAqMQswCQYDVQQGEwJVUzEM\r\n" +
        "MAoGA1UECgwDRFBTMQ0wCwYDVQQDDARyb290MB4XDTE4MDMwMTE4MTQzMloXDTI4\r\n" +
        "MDIyNzE4MTQzMlowOTELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0RQUzEcMBoGA1UE\r\n" +
        "AwwTRFBTIFRlc3QgU3Vic2NyaWJlcjCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE\r\n" +
        "AdPlr3YCutvRP0agz6KRmVVY4HuzS5zmEaBzkTCSWFkhugDgwmMgszDCAD5maqe5\r\n" +
        "nAHammIc/MSw1UK+JFLFzSffAB48lbymUgTtE41sXWx82gc6vwvU25DqnNxHgS0L\r\n" +
        "K0bVQweaXa4toICC3SLZD0iRDI1jUqZPwDCkbpF9LyDDa181MAoGCCqGSM49BAME\r\n" +
        "A4GLADCBhwJBP7gFuL3dePSkYG4LoBg1atH6+2xfJWg51ZV8diRXWIgRlC5u3kCQ\r\n" +
        "R+AJhf+Slik1tMQePTB5OojwrRYjw40iEDoCQgE6rg0vAE2AZVLYfVsz01we+Rov\r\n" +
        "L8bFbjmY7xtqNCqRgCP7Nb/DLED8ahqo+uI7tPx5EqxDWj0FdxewZnbnBorBug==\r\n" +
        "-----END CERTIFICATE-----\r\n";
    var subscriberPrivateKey = "-----BEGIN EC PRIVATE KEY-----\r\n" +
        "Proc-Type: 4,ENCRYPTED\r\n" +
        "DEK-Info: AES-256-CBC,65E2556079AC9649D58B8CC72AE4A43E\r\n" +
        "\r\n" +
        "qWEHBFDO16P65LBjQecIrcql5bWuUx2SO87Qgllm576xolusU+iTExRVENjtO3Nl\r\n" +
        "Vil2EqdMX2KHdv9p282lW1Drl069SesP69LiOo0sMYJefWJZRSnbRL7e7tDTXuUz\r\n" +
        "p038ythZg7Ho6UggO6cvy08JomqMuJtwpJ6RTTFAsQMsEqCF8m0e26EdxrFUpkrM\r\n" +
        "imwGuJ3hGzJKTZYaqK8i17LK+m4W0FzXETXp+qDyp9LBuZTqBISJ7MH+LOnY4neZ\r\n" +
        "a/F20EFCFwL47sfQlZMsOYHw140IS2+YOyzOD051Gbw=\r\n" +
        "-----END EC PRIVATE KEY-----\r\n";
    var subscriberPassword = "DPS Test Subscriber";
    var keyStore;
    var nodeId;
    var node;
    var pub;
    var pubKeyId;
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
            return dps.setKey(request, new dps.KeyCert(publisherCert, publisherPrivateKey, publisherPassword));
        }
        if (compare(subscriberId, id)) {
            return dps.setKey(request, new dps.KeyCert(subscriberCert));
        }
        return dps.ERR_MISSING;
    };
    var onEphemeralKey = function(request, key) {
        var ecdh;
        var n;
        var x, y, d;
        var pad;

        switch (key.type) {
        case dps.KEY_SYMMETRIC:
            return dps.setKey(request, new dps.KeySymmetric(crypto.randomBytes(32)));
        case dps.KEY_EC:
            switch (key.curve) {
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
            /* Must pad the private key to reach length n */
            if (d.length != n) {
                pad = Buffer.alloc(n - d.length, 0);
                d = Buffer.concat([pad, d], n);
            }
            return dps.setKey(request, new dps.KeyEC(key.curve, x, y, d));
        default:
            return dps.ERR_MISSING;
        }
    };
    var onCA = function(request) {
        return dps.setCA(request, ca);
    };

    var onAck = function (pub, payload) {
        console.log("Ack for pub UUID " + dps.publicationGetUUID(pub) + "(" + dps.publicationGetSequenceNum(pub) + ")");
        console.log("    " + payload);
    };
    var onDestroy = function (node) {
        dps.destroyKeyStore(keyStore);
    };
    var stop = function () {
        dps.destroyPublication(pub);
        dps.destroyNode(node, onDestroy);
    };
    var publish = function () {
        dps.publish(pub, "world", 0);
        console.log("Pub UUID " + dps.publicationGetUUID(pub) + "(" + dps.publicationGetSequenceNum(pub) + ")");
        setTimeout(stop, 1000);
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
        pubKeyId = null;
    } else if (encryption == 1) {
        keyStore = dps.createKeyStore(onKeyAndId, onKey, onEphemeralKey, null);
        nodeId = null;
        pubKeyId = keyID[0];
    } else if (encryption == 2) {
        keyStore = dps.createKeyStore(onKeyAndId, onKey, onEphemeralKey, onCA);
        nodeId = publisherId;
        pubKeyId = subscriberId;
    }

    node = dps.createNode("/", keyStore, nodeId);
    dps.startNode(node, dps.MCAST_PUB_ENABLE_SEND, null);
    console.log("Publisher is listening on " +  dps.getListenAddress(node));
    pub = dps.createPublication(node);

    dps.initPublication(pub, ["a/b/c"], false, null, onAck);
    dps.publicationAddSubId(pub, pubKeyId);
    dps.publish(pub, "hello", 0);
    console.log("Pub UUID " + dps.publicationGetUUID(pub) + "(" + dps.publicationGetSequenceNum(pub) + ")");
    setTimeout(publish, 1000);
}());
