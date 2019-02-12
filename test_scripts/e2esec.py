#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

def expect_signed_pub_received(subs, pattern, signed_count):
    ss = []
    expect_pub_received(subs, pattern, signers=ss)
    if sum(s == 'DPS Test Publisher' for s in ss) != signed_count:
        sys.exit(1)

def expect_signed_ack_received(pubs, signed_count):
    ss = []
    expect_ack_received(pubs, signers=ss)
    if sum(s == 'DPS Test Subscriber' for s in ss) != signed_count:
        sys.exit(1)

for S in range(0, 4):
    reset_logs()
    sub1 = sub('-x {} {}'.format(S, S))
    pub1 = pub('-x 0 -a {}'.format(S))
    pub2 = pub('-x 1 -a {}'.format(S))
    pub3 = pub('-x 2 -a {}'.format(S))
    pub4 = pub('-x 3 -a {}'.format(S))
    if S == 0:
        expect_signed_pub_received(sub1, ['{}'.format(S)] * 2, 0)
        expect_signed_ack_received([pub1, pub4], 0)
    elif S == 1:
        expect_signed_pub_received(sub1, ['{}'.format(S)] * 3, 0)
        expect_ack_received([pub1, pub2, pub4], 0)
    elif S == 2:
        expect_signed_pub_received(sub1, ['{}'.format(S)] * 3, 2)
        expect_signed_ack_received([pub1, pub3, pub4], 2)
    elif S == 3:
        expect_signed_pub_received(sub1, ['{}'.format(S)] * 2, 1)
        expect_ack_received([pub1, pub4], 1)
