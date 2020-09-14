#!/usr/bin/python

from __future__ import print_function
from common import *
import glob
import os
import pexpect
from pexpect import popen_spawn
import platform
import sys

timeout=300

if 'FSAN' not in os.environ or os.environ['FSAN'] == 'no':
    tests = [os.path.join('build', 'test', 'bin', 'cbortest'),
             os.path.join('build', 'test', 'bin', 'cosetest'),
             os.path.join('build', 'test', 'bin', 'countvec'),
             os.path.join('build', 'test', 'bin', 'hist_unit'),
             os.path.join('build', 'test', 'bin', 'jsontest'),
             os.path.join('build', 'test', 'bin', 'link'),
             os.path.join('build', 'test', 'bin', 'packtest'),
             os.path.join('build', 'test', 'bin', 'publish'),
             os.path.join('build', 'test', 'bin', 'pubsub'),
             os.path.join('build', 'test', 'bin', 'uuid'),
             os.path.join('build', 'test', 'bin', 'rle_compression'),
             os.path.join('build', 'test', 'bin', 'keystoretest'),
             os.path.join('test_scripts', 'auth.py'),
             os.path.join('test_scripts', 'chain_test.py'),
             os.path.join('test_scripts', 'e2esec.py'),
             os.path.join('test_scripts', 'fanout.py'),
             os.path.join('test_scripts', 'hot_mesh.py'),
             os.path.join('test_scripts', 'link_drop.py'),
             os.path.join('test_scripts', 'loop25.py'),
             os.path.join('test_scripts', 'loop3.py'),
             os.path.join('test_scripts', 'pub100.py'),
             os.path.join('test_scripts', 'reg1.py'),
             os.path.join('test_scripts', 'simple_discover.py'),
             os.path.join('test_scripts', 'simple_test.py'),
             os.path.join('test_scripts', 'topic_match.py'),
             os.path.join('test_scripts', 'tree0.py'),
             os.path.join('test_scripts', 'tree1.py'),
             os.path.join('test_scripts', 'tree2.py'),
             os.path.join('test_scripts', 'tutorial.py'),
             os.path.join('test_scripts', 'versioning.py')
    ]
    if 'BINDINGS' not in os.environ or 'all' in os.environ['BINDINGS'] or 'python' in os.environ['BINDINGS']:
        tests.extend([
            os.path.join('test_scripts', 'retained_py.py'),
            os.path.join('py_scripts', 'subs_tree.py'),
            os.path.join('test_scripts', 'simple_py_test.py'),
            os.path.join('test_scripts', 'simple_py_ks_test.py')
        ])
    if 'BINDINGS' in os.environ and ('all' in os.environ['BINDINGS'] or 'nodejs' in os.environ['BINDINGS']):
        tests.extend([
            os.path.join('test_scripts', 'simple_js_ks_test.py'),
            os.path.join('test_scripts', 'simple_js_test.py')
        ])
    if 'BINDINGS' not in os.environ or 'all' in os.environ['BINDINGS'] or 'go' in os.environ['BINDINGS']:
        tests.extend([
            os.path.join('test_scripts', 'simple_go_ks_test.py'),
            os.path.join('test_scripts', 'simple_go_test.py')
        ])
else:
    tests = [os.path.join('test_scripts', 'fuzzer_check.py')]
    #
    # DTLS fuzzer checks take a significant amount of time to complete
    # due to the number of steps and the timeouts during the handshake
    # errors
    #
    if os.environ['USE_DTLS'] == '1':
        timeout = 600

ok = 0
failed = 0
failed_tests = ''

def _dump_logs():
    for log in glob.glob('out/*.log'):
        size = os.path.getsize(log)
        with open(log, 'r') as l:
            print('==> {} <=='.format(log))
            if size > 32768:
                l.seek(-32768, os.SEEK_END)
            print(l.read(), end='')

for test in tests:
    reset_logs()
    print('[ RUN      ] ' + test)
    if test.startswith('test_scripts'):
        child = popen_spawn.PopenSpawn(['python', test] + sys.argv[1:], logfile=getattr(sys.stdout, 'buffer', sys.stdout))
        child.expect(pexpect.EOF, timeout=timeout)
        status = child.wait()
    elif test.startswith('py_scripts'):
        status = py([test] + sys.argv[1:])
    else:
        status = bin([test] + sys.argv[1:])
    if status == 0:
        print('[       OK ] ' + test)
        ok = ok + 1
    else:
        print('[   FAILED ] ' + test)
        failed = failed + 1
        failed_tests += '[   FAILED ] ' + test + '\n'
        _dump_logs()

print('[==========] {} tests ran.'.format(ok + failed))
if ok > 0:
    print('[  PASSED  ] {} tests.'.format(ok))
if failed > 0:
    print('[  FAILED  ] {} tests, listed below:'.format(failed))
    print(failed_tests)

sys.exit(failed)
