#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

# No wildcard matching
sub1 = discover('-s 1/1/1 -s 1/1/2')

discover('-w -p 1/1/1 -p 1/1/2')

expect_pub_received([sub1], '1/1/1')
expect_pub_received([sub1], '1/1/2')

# Wildcard matching
sub1 = discover('-s 1/1/#')

discover('-p 1/1/1 -p 1/1/2')

expect_pub_received([sub1], '1/1/1')
expect_pub_received([sub1], '1/1/2')
