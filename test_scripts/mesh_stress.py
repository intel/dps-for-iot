#!/usr/bin/python

from common import *
import atexit
import glob
import time

atexit.register(cleanup)

ms = []
meshes = glob.glob('test/meshes/*.txt')
for m in meshes:
    ms.append(mesh_stress(m))

# Watch for errors for 10 minutes
for i in range(10):
    time.sleep(60)
    for m in ms:
        try:
            m.expect('ERROR', timeout=0)
        except pexpect.TIMEOUT:
            print('TIMEOUT')
            pass

for m in ms:
    m.kill(signal.SIGTERM)
    try:
        m.expect('ERROR')
    except pexpect.EOF:
        pass
