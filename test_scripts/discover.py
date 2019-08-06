#!/usr/bin/python
#
# Example:
# $ ./test_scripts/discover.py
# $ ./tools/graph_nodes.pl out/* | neato -Tpng | display
#
# neato and sfdp appear to provide the nicest results.
#
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
    topics = list(range(1, 13))
    choices = ['-p ' + str(topic) for topic in topics]
    choices.extend(['-s ' + str(topic) for topic in topics])
    ns.append(discover(random.choice(choices)))

# Wait a bit for discovery to settle
time.sleep(10)

for n in ns:
    n.kill(signal.SIGUSR1)

time.sleep(1)
for n in ns:
    n.kill(signal.SIGTERM)
    try:
        n.expect('ERROR')
        raise RuntimeError('ERROR')
    except pexpect.EOF:
        pass
