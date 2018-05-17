#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

sub1 = sub('-w 1 T')
sub2 = sub('-w 1 -p {} A'.format(sub1.port))
sub3 = sub('-w 1 -p {} B'.format(sub2.port))

pub('-w 2 -p {} A'.format(sub3.port))
pub('-w 2 -p {} B'.format(sub2.port))

expect_pub_received(sub2, 'A')
expect_pub_received(sub3, 'B')
