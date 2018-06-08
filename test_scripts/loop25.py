#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

# loop

subs = [
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('A --'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('B --'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--'),
    sub('--')
]

for i in range(len(subs)):
    j = (i + len(subs) - 1) % len(subs)
    link(subs[i], subs[j].port)

for i in range(len(subs)):
    j = (i + len(subs) - 1) % len(subs)
    expect_linked(subs[i], subs[j].port)
