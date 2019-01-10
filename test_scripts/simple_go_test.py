#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

sub1 = go_sub()
go_pub()

expect_pub_received(sub1, ['a/b/c'] * 2)

#
# Verify interop between C sub and go pub
#
reset_logs()

sub1 = sub('a/b/c')
go_pub()

expect_pub_received(sub1, ['a/b/c'] * 2)

reset_logs()

sub1 = sub('-x 2 a/b/c')
go_pub('-x 2')

expect_pub_received(sub1, ['a/b/c'] * 2)

#
# Verify interop between go pub and C sub
#
reset_logs()

sub1 = go_sub()
pub('a/b/c')

expect_pub_received(sub1, 'a/b/c')

reset_logs()

sub1 = go_sub('-x 2')
pub('-x 2 a/b/c')

expect_pub_received(sub1, 'a/b/c')
