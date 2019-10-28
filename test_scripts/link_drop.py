#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

reps = 4
dropper = drop('-w 1 -t 2 -r {}'.format(reps))
subscriber = sub('--')

link(subscriber, dropper.port)

expect_dropped(dropper, subscriber.port, reps)
