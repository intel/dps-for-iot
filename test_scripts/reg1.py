#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

# Start the registry service
reg1 = reg()

# Start some subscribers

# Delay the starts so that we ensure a fully connected graph.
sub1 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
sub2 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked([sub1, sub2])
sub3 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub3)
sub4 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub4)
sub5 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub5)
sub6 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub6)
sub7 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub7)
sub8 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub8)
sub9 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub9)
sub10 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub10)
sub11 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub11)
sub12 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub12)
sub13 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub13)
sub14 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub14)
sub15 = reg_subs('-p {} --timeout 2000 a/b/c'.format(reg1.port))
expect_reg_linked(sub15)
sub16 = reg_subs('-p {} --timeout 2000 1/2/3'.format(reg1.port))
expect_reg_linked(sub16)
sub17 = reg_subs('-p {} --timeout 2000 +/+/#'.format(reg1.port))
expect_reg_linked(sub17)

# Start some publishers
reg_pubs('-p {} a/b/c -m hello'.format(reg1.port))
reg_pubs('-p {} 1/2/3 -m world'.format(reg1.port))

expect_pub_received([sub1, sub2, sub3, sub4, sub5, sub6, sub7, sub8, sub9, sub10, sub11, sub12,
		     sub13, sub14, sub15, sub17], 'a/b/c')
expect_pub_received([sub16, sub17], '1/2/3')
