#!/usr/bin/python

from common import *
import atexit
import glob
import random
import time

atexit.register(cleanup)

seed=1
num_nodes = 100

random.seed(seed)

ns = []
for i in range(num_nodes):
    ns.append(discover())

# Wait a bit for discovery to settle
time.sleep(10)

for n in ns:
    n.kill(signal.SIGTERM)
    try:
        n.expect('ERROR')
        raise RuntimeError('ERROR')
    except pexpect.EOF:
        pass
