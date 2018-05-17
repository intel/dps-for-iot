#!/usr/bin/python

import argparse
import collections
import copy
import os
import pexpect
from pexpect import popen_spawn
import signal
import shutil
import sys

os.putenv('PYTHONPATH', os.path.join('build', 'dist', 'py'))
os.putenv('NODE_PATH', os.path.join('build', 'dist', 'js'))

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action='store_true',
                    help="Enable debug ouput if built for debug.")
args = parser.parse_args()
if args.debug:
    debug = '-d'
else:
    debug = ''

children = []
logs = []
subs_rate = '-r 100'

n = 0
p = 0
s = 0
t = 0
v = 0

def _spawn_helper(n, cmd, interpreter=[]):
    global children, logs
    name = os.path.basename(cmd[0])
    log_name = 'out/{}{}.log'.format(name, n)
    log = open(log_name, 'wb')
    log.write('=============================\n{}{} {}\n'.format(name, n, ' '.join(cmd[1:])))
    log.write('=============================\n')
    cmd = interpreter + cmd
    child = popen_spawn.PopenSpawn(cmd, logfile=log)
    child.linesep = os.linesep
    children.append(child)
    logs.append(log)
    return child

def _spawn(n, cmd):
    return _spawn_helper(n, cmd)

def _py_spawn(n, cmd):
    child = _spawn_helper(n, cmd, ['python', '-u'])
    child.linesep = '\n'
    return child

def _js_spawn(n, cmd):
    return _spawn_helper(n, cmd, ['node'])

def _expect(children, pattern, allow_error=False, timeout=-1):
    if not allow_error:
        pattern.append('ERROR')
    for child in children:
        i = child.expect(pattern, timeout)
        if i != 0:
            raise RuntimeError(pattern[i])

def _expect_listening(child):
    _expect([child], ['is listening on port (\d+)'])
    child.port = int(child.match.group(1))

def _expect_linked(child, args):
    ports = []
    prev = ''
    for curr in args.split():
        if prev == '-p':
            ports.append(curr)
        prev = curr
    while len(ports):
        _expect([child], ['is linked to \S+/(\d+)'])
        ports.remove(child.match.group(1))

def expect_linked(child, ports):
    if not isinstance(ports, collections.Sequence):
        ports = [ports]
    _expect_linked(child, ('-p {} ' * len(ports)).format(*ports))

def _expect_pub(children, topics, allow_error=False, timeout=-1):
    for child in children:
        patterns = []
        for topic in topics:
            patterns.append('pub {}{}'.format(' | '.join(topic.split()), child.linesep))
        while len(patterns):
            if not allow_error:
                i = child.expect(['ERROR'] + patterns, timeout=timeout)
                if i == 0:
                    raise RuntimeError('ERROR')
            else:
                child.expect(patterns, timeout=timeout)
            patterns.remove(child.match.re.pattern)

def cleanup():
    global children
    for child in children:
        child.kill(signal.SIGTERM)
        child.read()
    for child in children:
        child.wait()
    children = []
    for log in logs:
        log.close()

def reset_logs():
    global n, p, s, t, v
    n = 0
    p = 0
    s = 0
    t = 0
    v = 0
    cleanup()
    shutil.rmtree('out', ignore_errors=True)
    try:
        os.makedirs('out')
    except OSError:
        if not os.path.isdir('out'):
            raise

def node(args):
    global n
    n = n + 1
    cmd = [os.path.join('build', 'test', 'bin', 'node')] + debug.split() + args.split()
    child = _spawn(n, cmd)
    _expect([child], ['Ready'])
    return child

def sub(args=''):
    global s
    s = s + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'subscriber')] + debug.split() + subs_rate.split() + args.split()
    child = _spawn(s, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def pub(args):
    global p
    p = p + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'publisher'), '-w', '1'] + debug.split() + subs_rate.split() + args.split()
    child = _spawn(p, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def py_sub(args=''):
    global s
    s = s + 1
    cmd = [os.path.join('py_scripts', 'simple_sub.py')] + debug.split() + args.split()
    child = _py_spawn(s, cmd)
    _expect_listening(child)
    return child

def py_pub(args=''):
    global p
    p = p + 1
    cmd = [os.path.join('py_scripts', 'simple_pub.py')] + debug.split() + args.split()
    child = _py_spawn(p, cmd)
    _expect_listening(child)
    return child

def py_late_sub():
    global s
    s = s + 1
    cmd = [os.path.join('py_scripts', 'late_sub.py')] + debug.split()
    child = _py_spawn(s, cmd)
    _expect_listening(child)
    return child

def py_retained_pub():
    global p
    p = p + 1
    cmd = [os.path.join('py_scripts', 'retained_pub.py')] + debug.split()
    child = _py_spawn(p, cmd)
    _expect_listening(child)
    return child

def py_sub_ks(args=''):
    global s
    s = s + 1
    cmd = [os.path.join('py_scripts', 'simple_sub_ks.py')] + debug.split() + args.split()
    child = _py_spawn(s, cmd)
    _expect_listening(child)
    return child

def py_pub_ks(args=''):
    global p
    p = p + 1
    cmd = [os.path.join('py_scripts', 'simple_pub_ks.py')] + debug.split() + args.split()
    child = _py_spawn(p, cmd)
    _expect_listening(child)
    return child

def js_sub(args=''):
    global s
    s = s + 1
    cmd = [os.path.join('js_scripts', 'simple_sub.js')] + debug.split() + args.split()
    child = _js_spawn(s, cmd)
    _expect_listening(child)
    return child

def js_pub(args=''):
    global p
    p = p + 1
    cmd = [os.path.join('js_scripts', 'simple_pub.js')] + debug.split() + args.split()
    child = _js_spawn(p, cmd)
    _expect_listening(child)
    return child

def js_sub_ks(args=''):
    global s
    s = s + 1
    cmd = [os.path.join('js_scripts', 'simple_sub_ks.js')] + debug.split() + args.split()
    child = _js_spawn(s, cmd)
    _expect_listening(child)
    return child

def js_pub_ks(args=''):
    global p
    p = p + 1
    cmd = [os.path.join('js_scripts', 'simple_pub_ks.js')] + debug.split() + args.split()
    child = _js_spawn(p, cmd)
    _expect_listening(child)
    return child

def tutorial(args=''):
    global t
    t = t + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'tutorial')] + debug.split() + args.split()
    child = _spawn(t, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def ver(args=''):
    global v
    v = v + 1
    cmd = [os.path.join('build', 'test', 'bin', 'version')] + debug.split() + args.split()
    child = _spawn(v, cmd)
    _expect_listening(child)
    return child

def link(child, ports):
    if not isinstance(ports, collections.Sequence):
        ports = [ports]
    child.sendline(('-p {} ' * len(ports)).format(*ports))

def expect(children, pattern, allow_error=False, timeout=-1):
    if not isinstance(children, collections.Sequence):
        children = [children]
    if isinstance(pattern, str):
        pattern = [pattern]
    _expect(children, pattern, allow_error, timeout)

def expect_pub_received(children, topic, allow_error=False, timeout=-1):
    if not isinstance(children, collections.Sequence):
        children = [children]
    if isinstance(topic, str):
        topic = [topic]
    _expect_pub(children, topic, allow_error, timeout)

def expect_pub_not_received(children, topic, allow_error=False):
    try:
        expect_pub_received(children, topic, allow_error, 1)
    except pexpect.TIMEOUT:
        return
    raise RuntimeError(topic)

def expect_ack_received(children, allow_error=False):
    expect(children, 'Ack for pub')

def expect_error(children, error):
    expect(children, 'ERROR.*{}'.format(error))

reset_logs()
