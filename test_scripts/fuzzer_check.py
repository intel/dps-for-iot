#!/usr/bin/python

from common import *
import atexit
import glob

atexit.register(cleanup)

def _fuzzer_check(fuzzer, corpus):
    while corpus:
        # Work around max argument length by slicing
        bin(fuzzer + corpus[:1024])
        del corpus[:1024]

if os.environ['USE_DTLS'] == '0':
    _fuzzer_check([os.path.join('build', 'test', 'bin', 'cbor_fuzzer')],
                  glob.glob('test/corpus/cbor/*'))
    _fuzzer_check([os.path.join('build', 'test', 'bin', 'multicast_receive_fuzzer')],
                  glob.glob('test/corpus/multicast_receive/*'))
    _fuzzer_check([os.path.join('build', 'test', 'bin', 'net_receive_fuzzer')],
                  glob.glob('test/corpus/unicast_receive/*'))
else:
    for step in range(7):
        _fuzzer_check([os.path.join('build', 'test', 'bin', 'dtls_fuzzer'), 'server', '{}'.format(step)],
                      glob.glob('test/corpus/dtls_server_{}/*'.format(step)))
    for step in range(8):
        _fuzzer_check([os.path.join('build', 'test', 'bin', 'dtls_fuzzer'), 'client', '{}'.format(step)],
                      glob.glob('test/corpus/dtls_client_{}/*'.format(step)))


