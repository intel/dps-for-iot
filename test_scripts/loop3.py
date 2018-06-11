#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

subs = [
    sub('A --'),
    sub('B --'),
    sub('C --')
]

for i in range(len(subs)):
    j = (i + 1) % len(subs)
    link(subs[i], subs[j].port)

for i in range(len(subs)):
    j = (i + 1) % len(subs)
    expect_linked(subs[i], subs[j].port)
