var dps = require('dps');

var simple_sub = (function(){
    var onPub = function(sub, pub, payload) {
        console.log("Pub " + dps.PublicationGetUUID(pub) + "/" + dps.PublicationGetSerialNumber(pub));
        console.log("Payload " +  payload);
        ack = dps.CreatePublicationAck(pub);
        dps.AckPublication(ack, "Acking " + dps.PublicationGetSerialNumber(pub));
        dps.DestroyPublicationAck(ack);
    };

    /* Set to 1 to enable DPS debug output */
    dps.Debug = 1;

    var node = dps.CreateNode("/");
    dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0);
    var sub = dps.CreateSubscription(node, ['a/b/c']);
    dps.Subscribe(sub, onPub);
})();
