#!/usr/bin/python

from __future__ import print_function
from common import *
import glob
import os
import multiprocessing
from multiprocessing import Pool
import pexpect
from pexpect import popen_spawn
import platform
import sys

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
             os.path.join('build', 'test', 'bin', 'rle_compression'),
             os.path.join('build', 'test', 'bin', 'keystoretest'),
             os.path.join('test_scripts', 'auth.py'),
             os.path.join('test_scripts', 'chain_test.py'),
             os.path.join('test_scripts', 'e2esec.py'),
             os.path.join('test_scripts', 'fanout.py'),
             os.path.join('test_scripts', 'hot_mesh.py'),
             os.path.join('test_scripts', 'loop25.py'),
             os.path.join('test_scripts', 'loop3.py'),
             os.path.join('test_scripts', 'pub100.py'),
             os.path.join('test_scripts', 'reg1.py'),
             os.path.join('test_scripts', 'simple_test.py'),
             os.path.join('test_scripts', 'topic_match.py'),
             os.path.join('test_scripts', 'tree0.py'),
             os.path.join('test_scripts', 'tree1.py'),
             os.path.join('test_scripts', 'tree2.py'),
             os.path.join('test_scripts', 'tutorial.py'),
             os.path.join('test_scripts', 'versioning.py'),
             os.path.join('test_scripts', 'retained_py.py'),
    ]
    if 'BINDINGS' not in os.environ or 'all' in os.environ['BINDINGS'] or 'python' in os.environ['BINDINGS']:
        tests.extend([
            os.path.join('py_scripts', 'subs_tree.py'),
             os.path.join('test_scripts', 'simple_py_test.py'),
             os.path.join('test_scripts', 'simple_py_ks_test.py')
        ])
    if 'BINDINGS' not in os.environ or 'all' in os.environ['BINDINGS'] or 'nodejs' in os.environ['BINDINGS']:
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

def run_test(args):
    (transport, test) = args
    reset_logs(transport, test)
    name = os.path.join(transport, test)
    print('[ RUN      ] ' + name)
    if test.startswith('test_scripts'):
        child = popen_spawn.PopenSpawn(['python', test, '-n', transport] + sys.argv[1:], logfile=sys.stdout)
        child.expect(pexpect.EOF, timeout=300)
        status = child.wait()
    elif test.startswith('py_scripts'):
        status = py([test, '-n', transport] + sys.argv[1:])
    else:
        status = bin([test, '-n', transport] + sys.argv[1:])
    if status == 0:
        print('[       OK ] ' + name)
    else:
        print('[   FAILED ] ' + name)
        dump_logs(name)
    return (name, status)

args = []
for transport in os.environ['TRANSPORT'].split(','):
    for test in tests:
        args = args + [(transport, test)]

pool = Pool()
results = pool.map(run_test, args)

ok = 0
failed = 0
failed_tests = ''
for result in results:
    (name, status) = result
    if status == 0:
        ok = ok + 1
    else:
        failed = failed + 1
        failed_tests += '[   FAILED ] ' + name + '\n'

print('[==========] {} tests ran.'.format(ok + failed))
if ok > 0:
    print('[  PASSED  ] {} tests.'.format(ok))
if failed > 0:
    print('[  FAILED  ] {} tests, listed below:'.format(failed))
    print(failed_tests)

sys.exit(failed)
