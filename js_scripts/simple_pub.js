var dps = require('dps');

var simple_pub = (function(){
    var onAck = function(pub, payload) {
        console.log("PubAck " + dps.PublicationGetUUID(pub) + "/" + dps.PublicationGetSequenceNum(pub));
        console.log("Payload " + payload);
    };
    var publish = function() {
        dps.Publish(pub, "world", 0);
        setTimeout(stop, 100);
    };
    var stop = function() {
        dps.DestroyPublication(pub);
        dps.DestroyNode(node);
    }
    var onNode = function(node, kid, key, keylen) {
        console.log("Key Request Callback");
        return 0;
    };
    /* Set to 1 to enable DPS debug output */
    dps.Debug = 1;

    var node = dps.CreateNode("/", onNode, 0);
    dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, 0);
    var pub = dps.CreatePublication(node);

    dps.InitPublication(pub, ['a/b/c'], 0, onAck);
    dps.Publish(pub, "hello", 0);
    setTimeout(publish, 100);
})();
