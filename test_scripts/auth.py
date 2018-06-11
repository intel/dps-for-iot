#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

#
# Participants
# - Alice :: authorized to publish data on topic T
# - Bob :: authorized to subscribe to data on topic T
# - Eve :: eavesdropper who is not authorized to subscribe
# - Trudy :: intruder who is not authorized to publish or acknowledge
#

#
# Unauthorized subscription
# - To protect against Eve, Alice must encrypt for Bob to prevent Eve from eavesdropping.
#
reset_logs()

node1 = node('-u bob -s T')
node2 = node('-u eve -s T')
node3 = node('-u alice -p T')

expect_pub_received(node1, 'T')
expect_pub_not_received(node2, 'T', allow_error=True)

#
# Unauthorized publication
# - To protect against Trudy, Bob must know that Alice is not the originator.
#
reset_logs()

node1 = node('-u bob -s T')
node2 = node('-u trudy -p T')

expect_error(node1, 'Unauthorized pub')

#
# Unauthorized acknowledgement
# - To protect against Trudy, Alice must know that Bob is not the originator.
#
reset_logs()

node1 = node('-u bob -s T')
node2 = node('-u trudy -s T')
node3 = node('-u alice -p T')

expect_pub_received([node1, node2], 'T', allow_error=True)
expect_error(node3, 'Unauthorized ack')
