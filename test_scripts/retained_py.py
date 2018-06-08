#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

py_retained_pub()
sub1 = py_late_sub()

expect_pub_received(sub1, 'a/b/c')
