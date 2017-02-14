var dps = require('dps');

var simple_sub = (function(){
    var onPub = function(sub, pub, payload) {
        console.log("Pub " + dps.PublicationGetUUID(pub) + "/" + dps.PublicationGetSequenceNum(pub));
        console.log("Payload " +  payload);
        ack = "Acking " + dps.PublicationGetSequenceNum(pub)
        dps.AckPublication(pub, ack);
    };
    var onNode = function(node, kid, key, keylen) {
        console.log("Key Request Callback");
        return 0;
    };

    /* Set to 1 to enable DPS debug output */
    dps.Debug = 1;

    var node = dps.CreateNode("/", onNode, 0);
    dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0);
    var sub = dps.CreateSubscription(node, ['a/b/c']);
    dps.Subscribe(sub, onPub);
})();
