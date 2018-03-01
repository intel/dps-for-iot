"use strict";
var dps = require("dps");

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
    var sub;
    var i;
    var encryption;

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

    keyStore = dps.createMemoryKeyStore();
    dps.setNetworkKey(keyStore, networkKeyID, networkKey);
    if (encryption == 0) {
        nodeId = null;
    } else if (encryption == 1) {
        for (i = 0; i < keyID.length; i += 1) {
            dps.setContentKey(keyStore, keyID[i], keyData[i]);
        }
        nodeId = null;
    } else if (encryption == 2) {
        dps.setTrustedCA(keyStore, ca);
        dps.setCertificate(keyStore, subscriberCert, subscriberPrivateKey, subscriberPassword);
        dps.setCertificate(keyStore, publisherCert);
        nodeId = subscriberId;
    }

    node = dps.createNode("/", keyStore, nodeId);
    dps.startNode(node, dps.MCAST_PUB_ENABLE_RECV, 0);
    sub = dps.createSubscription(node, ["a/b/c"]);
    dps.subscribe(sub, onPub);
}());
