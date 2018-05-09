#!/usr/bin/python

import os
import pexpect
from pexpect import popen_spawn
import sys

os.putenv('PYTHONPATH', os.path.join('build', 'dist', 'py'))
os.putenv('NODE_PATH', os.path.join('build', 'dist', 'js'))

tests = [os.path.join('build', 'test', 'bin', 'cbortest'),
         os.path.join('build', 'test', 'bin', 'cosetest'),
         os.path.join('build', 'test', 'bin', 'countvec'),
         os.path.join('build', 'test', 'bin', 'hist_unit'),
         os.path.join('build', 'test', 'bin', 'packtest'),
         os.path.join('build', 'test', 'bin', 'publish'),
         os.path.join('build', 'test', 'bin', 'pubsub'),
         os.path.join('build', 'test', 'bin', 'publish'),
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
         os.path.join('py_scripts', 'subs_tree.py'),
         os.path.join('test_scripts', 'retained_py.py'),
         os.path.join('test_scripts', 'simple_js_ks_test.py'),
         os.path.join('test_scripts', 'simple_js_test.py'),
         os.path.join('test_scripts', 'simple_py_test.py'),
         os.path.join('test_scripts', 'simple_py_ks_test.py')
]

ok = 0
failed = 0
failed_tests = ''

for test in tests:
    print('[ RUN      ] ' + test)
    if test.endswith('.py'):
        cmd = 'python ' + test
    else:
        cmd = test
    status = popen_spawn.PopenSpawn(cmd).wait()
    if status == 0:
        print('[       OK ] ' + test)
        ok = ok + 1
    else:
        print('[   FAILED ] ' + test)
        failed = failed + 1
        failed_tests += '[   FAILED ] ' + test + '\n'

print('[==========] {} tests ran.'.format(ok + failed))
if ok > 0:
    print('[  PASSED  ] {} tests.'.format(ok))
if failed > 0:
    print('[  FAILED  ] {} tests, listed below:'.format(failed))
    print(failed_tests)

sys.exit(failed)
