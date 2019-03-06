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

# Watch for errors for ~10 minutes
for i in range(10):
    time.sleep(60)
    for m in ms:
        try:
            # timeout=0 doesn't catch errors for some reason
            m.expect('ERROR', timeout=1)
            raise RuntimeError('ERROR')
        except pexpect.TIMEOUT:
            print('TIMEOUT')
            pass

for m in ms:
    m.kill(signal.SIGTERM)
    try:
        m.expect('ERROR')
        raise RuntimeError('ERROR')
    except pexpect.EOF:
        pass
