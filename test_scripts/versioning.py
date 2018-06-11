#!/usr/bin/python

from common import *
import atexit
import os

atexit.register(cleanup)

#
# Verify that all 4 packet types are sent/received with version property
#

# Multicast
sub1 = sub('A')
pub1 = pub('-a A')

expect_pub_received(sub1, 'A')
expect(pub1, 'Ack for pub')

# Unicast
sub2 = sub('-p {} A'.format(sub1.port))
pub2 = pub('-p {} -a A'.format(sub1.port))

expect_pub_received([sub1, sub2], 'A')
expect(pub2, ['Ack for pub'] * 2)

#
# Verify that unsupported version is dropped
#
# Multicast
reset_logs()

sub1 = sub('A')
ver('-v 2')

expect(sub1, 'ERROR.*Expected message version 1, received 2')

# Unicast
reset_logs()

sub1 = sub('A')
ver('-p {} -v 2'.format(sub1.port))

expect(sub1, 'ERROR.*Expected message version 1, received 2')

#
# Verify that unsupported message type is dropped
#
# Multicast
reset_logs()

sub1 = sub('A')
ver('-v 1 -t 5')

expect(sub1, 'ERROR.*Invalid message type')

# Unicast
reset_logs()

sub1 = sub('A')
ver('-p {} -v 1 -t 5'.format(sub1.port))

expect(sub1, 'ERROR.*Invalid message type')
