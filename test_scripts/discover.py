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
topics = list(range(ord('A'), ord('A') + 12))

random.seed(seed)

def n_sub(n):
    ns = []
    choices = []
    for i in range(n):
        topic = random.choice(topics)
        choices.append(topic)
        ns.append(discover('-s %c' % (topic)))
    for i in range(n, num_nodes):
        ns.append(discover('-p %c' % (random.choice(choices))))
    return ns

def n_pub(n):
    ns = []
    choices = []
    for i in range(n):
        topic = random.choice(topics)
        choices.append(topic)
        ns.append(discover('-p %c' % (topic)))
    for i in range(n, num_nodes):
        ns.append(discover('-s %c' % (random.choice(choices))))
    return ns

def n_pub_one_topic(n):
    ns = []
    choices = []
    for i in range(n):
        ns.append(discover('-p A'))
    for i in range(n, num_nodes):
        ns.append(discover('-s A'))
    return ns

def pub_or_sub():
    ns = []
    for i in range(num_nodes):
        choices = ['-p ' + chr(topic) for topic in topics]
        choices.extend(['-s ' + chr(topic) for topic in topics])
        ns.append(discover(random.choice(choices)))
    return ns

# Select a topology:
#ns = n_sub(1)
#ns = n_pub(2)
#ns = n_pub_one_topic(2)
ns = pub_or_sub()

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
