#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

sub1 = sub('1/1/1')
sub2 = sub('+/+/1')
sub3 = sub('1/1/1 1/1/2')
sub4 = sub('1/1/1 1/1/2 1/1/3')
sub5 = sub('1/1/#')
sub6 = sub('2/#')
sub7 = sub('3/# 2/# 1/#')

pub('1/1/1 1/1/2 1/1/3')
pub('2/1/1 1/1/4')
pub('2/1/1 3/1/1')
pub('2/1/1 1/1/4 3/1/1')
pub('3/2 2/3')

expect_pub_received([sub1, sub2, sub3, sub4, sub5], '1/1/1 1/1/2 1/1/3')
expect_pub_received([sub2, sub5, sub6], '2/1/1 1/1/4')
expect_pub_received([sub2, sub6], '2/1/1 3/1/1')
expect_pub_received([sub2, sub5, sub6, sub7], '2/1/1 1/1/4 3/1/1')
expect_pub_received([sub6], '3/2 2/3')
