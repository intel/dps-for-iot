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
num_nodes = 30

random.seed(seed)

ns = []
for i in range(num_nodes):
    pubs = random.choice(["A"])
    subs = random.choice(["A"])
#    pubs = random.choice(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"])
#    subs = random.choice(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"])
    ns.append(discover("-p " + pubs + " -s " + subs))

# Wait a bit for discovery to settle
time.sleep(num_nodes)

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
