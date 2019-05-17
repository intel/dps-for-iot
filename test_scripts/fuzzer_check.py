#!/usr/bin/python

from common import *
import atexit
import glob

atexit.register(cleanup)

def _fuzzer_check(test, cmd_args, corpus):
    # Work around max argument length by slicing corpus args
    transport = args.network
    while corpus:
        reset_logs(transport, test)
        name = os.path.join(transport, test)
        print('[ RUN      ] ' + name)
        status = bin_log(os.path.join('out', transport, test), [test] + cmd_args + corpus[:1024])
        if status == 0:
            print('[       OK ] ' + name)
        else:
            print('[   FAILED ] ' + name)
            dump_logs(name)
            sys.exit(status)
        del corpus[:1024]

if args.network != 'dtls':
    _fuzzer_check(os.path.join('build', 'test', 'bin', 'cbor_fuzzer'), [],
                  glob.glob('test/corpus/cbor/*'))
    _fuzzer_check(os.path.join('build', 'test', 'bin', 'multicast_receive_fuzzer'), [],
                  glob.glob('test/corpus/multicast_receive/*'))
    _fuzzer_check(os.path.join('build', 'test', 'bin', 'net_receive_fuzzer'), [],
                  glob.glob('test/corpus/unicast_receive/*'))
else:
    for step in range(7):
        _fuzzer_check(os.path.join('build', 'test', 'bin', 'dtls_fuzzer'), ['server', '{}'.format(step)],
                      glob.glob('test/corpus/dtls_server_{}/*'.format(step)))
    for step in range(8):
        _fuzzer_check(os.path.join('build', 'test', 'bin', 'dtls_fuzzer'), ['client', '{}'.format(step)],
                      glob.glob('test/corpus/dtls_client_{}/*'.format(step)))
