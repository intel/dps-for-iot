#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

sub1 = sub('-w 1 -s X -s A')
sub2 = sub('-w 1 -p {} -s X -s B'.format(sub1.port))
sub3 = sub('-w 1 -p {} -s X -s C'.format(sub2.port))
sub4 = sub('-w 1 -p {} -s X -s D'.format(sub3.port))
sub5 = sub('-w 1 -p {} -s X -s E'.format(sub4.port))
sub6 = sub('-w 1 -p {} -s X -s F'.format(sub5.port))
sub7 = sub('-w 1 -p {} -s X -s G'.format(sub6.port))
sub8 = sub('-w 1 -p {} -s X -s H'.format(sub7.port))
sub9 = sub('-w 1 -p {} -s X -s I'.format(sub8.port))
sub10 = sub('-w 1 -p {} -s X -s J'.format(sub9.port))
sub11 = sub('-w 1 -p {} -s X -s K'.format(sub10.port))

# Link to all nodes in chain
sub12 = sub('-w 2 -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -s X -s L'.format(
    sub1.port, sub2.port, sub3.port, sub4.port, sub5.port, sub6.port, sub7.port, sub8.port, sub9.port, sub10.port, sub11.port))
sub13 = sub('-w 2 -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -s X -s M'.format(
    sub11.port, sub10.port, sub9.port, sub8.port, sub7.port, sub6.port, sub5.port, sub4.port, sub3.port, sub2.port, sub1.port))
sub14 = sub('-w 2 -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -p {} -s X -s N'.format(
    sub9.port, sub8.port, sub5.port, sub7.port, sub11.port, sub1.port, sub3.port, sub10.port, sub6.port, sub4.port, sub2.port))

subs = [
    sub1, sub2, sub3, sub4, sub5, sub6, sub7, sub8, sub9, sub10, sub11, sub12, sub13, sub14
]

pubs = [
    pub('-p {} A B C D E F G H I J K L M N'.format(sub1.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub2.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub3.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub4.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub5.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub6.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub7.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub8.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub9.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub10.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub11.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub12.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub13.port)),
    pub('-p {} A B C D E F G H I J K L M N'.format(sub14.port))
]

expect_pub_received(subs, ['A B C D E F G H I J K L M N'] * len(pubs))

# Reachability check

pub('-p {} X'.format(sub6.port))

expect_pub_received(subs, 'X')
