#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

sub1 = sub('-m 1.1')
sub2 = sub('-p {} 2.1'.format(sub1.port))
sub3 = sub('-p {} 3.1'.format(sub2.port))
sub4 = sub('-p {} +.1'.format(sub3.port));

pub1 = pub('1.1 2.1 3.1 4.1')

expect_pub_received([sub1, sub2, sub3, sub4], '1.1 2.1 3.1 4.1')
