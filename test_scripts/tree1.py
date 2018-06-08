#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

#
#   a/b/c ----\                                   /---- 1/2/3
#              \                                 /
#   d/e/f ------> A/A -------> B/B <------- C/C <------ 4/5/6
#              /                                 \
#   g/h/i ----/                                   \---- 7/8/9
#

sub1 = sub('B/B')
sub2 = sub('-p {} A/A'.format(sub1.port))
sub3 = sub('-p {} C/C'.format(sub1.port))

sub4 = sub('-p {} a/b/c'.format(sub2.port))
sub5 = sub('-p {} d/e/f'.format(sub2.port))
sub6 = sub('-p {} g/h/i'.format(sub2.port))

sub7 = sub('-p {} 1/2/3'.format(sub3.port))
sub8 = sub('-p {} 4/5/6'.format(sub3.port))
sub9 = sub('-p {} 7/8/9'.format(sub3.port))

pub1 = pub('-p {} a/b/c 4/5/6'.format(sub1.port))
pub2 = pub('-p {} d/e/f'.format(sub2.port))
pub3 = pub('-p {} 1/2/3'.format(sub4.port))
pub4 = pub('-p {} g/h/i'.format(sub3.port))

expect_pub_received([sub4, sub8], 'a/b/c 4/5/6')
expect_pub_received(sub5, 'd/e/f')
expect_pub_received(sub7, '1/2/3')
expect_pub_received(sub6, 'g/h/i')

# Now some retained pubs
#
#   a/b/c ----\                                   /---- 1/2/3 <----- +/#
#              \                                 /
#   d/e/f ------> A/A -------> B/B <------- C/C <------ 4/5/6
#              /                                 \
#   g/h/i ----/                                   \---- 7/8/9
#
#
sub10 = sub('-p {} +/#'.format(sub7.port))

pub5 = pub('-t 20 -p {} X/X'.format(sub4.port))
pub6 = pub('-t 20 -p {} Y/Y'.format(sub7.port))
pub7 = pub('-t 20 -p {} Z/Z'.format(sub2.port))

expect_pub_received(sub10, ['X/X', 'Y/Y', 'Z/Z'])

#   a/b/c ----\                                   /---- 1/2/3 <----- +/#
#              \                                 /
#   d/e/f ------> A/A -------> B/B <------- C/C <------ 4/5/6
#              /                ^                \
#   g/h/i ----/                 |                 \---- 7/8/9
#                               |
#

sub11 = sub('-p {} +/#'.format(sub1.port))

expect_pub_received(sub11, ['X/X', 'Y/Y', 'Z/Z'])
