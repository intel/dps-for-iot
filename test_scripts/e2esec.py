#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

for S in range(0, 3):
    reset_logs()
    sub1 = sub('-x {} {}'.format(S, S))
    pub1 = pub('-x 0 -a {}'.format(S))
    pub2 = pub('-x 1 -a {}'.format(S))
    pub3 = pub('-x 2 -a {}'.format(S))
    if S == 0:
	expect_pub_received(sub1, '{}'.format(S))
	expect_ack_received(pub1)
    elif S == 1:
	expect_pub_received(sub1, ['{}'.format(S)] * 2)
	expect_ack_received([pub1, pub2])
    elif S == 2:
	expect_pub_received(sub1, ['{}'.format(S)] * 2)
	expect_ack_received([pub1, pub3])
