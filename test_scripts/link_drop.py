#!/usr/bin/python

from common import *
import atexit

atexit.register(cleanup)

reps = 4
dropper = drop('-w 5 -t 1 -r {}'.format(reps))
subscriber = sub('-f 1 --')

link(subscriber, dropper.port)

expect_dropped(dropper, reps)
