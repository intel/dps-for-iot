var dps = require('dps');

var simple_sub = (function(){
    var onPub = function(sub, pub, payload) {
        console.log("Pub " + dps.PublicationGetUUID(pub) + "/" + dps.PublicationGetSequenceNum(pub));
        console.log("Payload " +  payload);
        ack = "Acking " + dps.PublicationGetSequenceNum(pub)
        dps.AckPublication(pub, ack);
    };

    /* Set to 1 to enable DPS debug output */
    dps.Debug = 1;

    var node = dps.CreateNode("/", null, 0);
    dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0);
    var sub = dps.CreateSubscription(node, ['a/b/c']);
    dps.Subscribe(sub, onPub);
})();
