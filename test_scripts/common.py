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

os.environ['USE_DTLS'] = '0'
try:
    if os.environ['TRANSPORT'] == 'dtls':
        os.environ['USE_DTLS'] = '1'
except KeyError:
    pass

os.environ['PYTHONPATH'] = os.path.join('build', 'dist', 'py')
os.environ['NODE_PATH'] = os.path.join('build', 'dist', 'js')

_parser = argparse.ArgumentParser()
_parser.add_argument("-d", "--debug", action='store_true',
                    help="Enable debug ouput if built for debug.")
_args = _parser.parse_args()
if _args.debug:
    _debug = ['-d']
else:
    _debug = []

_children = []
_logs = []
_subs_rate = ['-r', '100']

_ms = 0
_n = 0
_p = 0
_r = 0
_rp = 0
_rs = 0
_s = 0
_t = 0
_tm = 0
_v = 0

def _spawn_helper(n, cmd, interpreter=[]):
    global _children, _logs
    name = os.path.basename(cmd[0])
    log_name = 'out/{}{}.log'.format(name, n)
    log = open(log_name, 'wb')
    log.write('=============================\n{}{} {}\n'.format(name, n, ' '.join(cmd[1:])))
    log.write('=============================\n')
    cmd = interpreter + cmd
    child = popen_spawn.PopenSpawn(cmd, logfile=log)
    child.linesep = os.linesep
    _children.append(child)
    _logs.append(log)
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
    _expect([child], ['is listening on port (\d+){}'.format(child.linesep)])
    child.port = int(child.match.group(1))

def _expect_linked(child, args):
    ports = []
    prev = ''
    for curr in args.split():
        if prev == '-p':
            ports.append(curr)
        prev = curr
    while len(ports):
        _expect([child], ['is linked to \S+/(\d+){}'.format(child.linesep)])
        ports.remove(child.match.group(1))

def expect_linked(child, ports):
    if not isinstance(ports, collections.Sequence):
        ports = [ports]
    _expect_linked(child, ('-p {} ' * len(ports)).format(*ports))

def _expect_pub(children, topics, allow_error=False, timeout=-1):
    for child in children:
        patterns = []
        for topic in topics:
            patterns.append('pub {}'.format(' \| '.join(topic.split())))
        patterns = ['(' + '|'.join(patterns) + '){}'.format(child.linesep)] * len(topics)
        while len(patterns):
            if not allow_error:
                i = child.expect(['ERROR'] + patterns, timeout=timeout)
                if i == 0:
                    raise RuntimeError('ERROR')
            else:
                child.expect(patterns, timeout=timeout)
            patterns.remove(child.match.re.pattern)

def cleanup():
    global _children
    for child in _children:
        child.kill(signal.SIGTERM)
        child.read()
    for child in _children:
        child.wait()
    _children = []
    for log in _logs:
        log.close()

def reset_logs():
    global _ms, _n, _p, _r, _rp, _rs, _s, _t, _tm, _v
    _ms = 0
    _n = 0
    _p = 0
    _r = 0
    _rp = 0
    _rs = 0
    _s = 0
    _t = 0
    _tm = 0
    _v = 0
    cleanup()
    shutil.rmtree('out', ignore_errors=True)
    try:
        os.makedirs('out')
    except OSError:
        if not os.path.isdir('out'):
            raise

def bin(cmd):
    global _children
    child = _spawn(1, cmd)
    buf = child.read(8192)
    while buf:
        buf = child.read(8192)
    status = child.wait()
    _children.remove(child)
    return status

def py(cmd):
    global _children
    child = _py_spawn(1, cmd)
    child.expect(pexpect.EOF, timeout=300)
    status = child.wait()
    _children.remove(child)
    return status

def node(args):
    global _n
    _n = _n + 1
    cmd = [os.path.join('build', 'test', 'bin', 'node')] + _debug + args.split()
    child = _spawn(_n, cmd)
    _expect([child], ['Ready'])
    return child

def sub(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'subscriber')] + _debug + _subs_rate + args.split()
    child = _spawn(_s, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def pub(args):
    global _p
    _p = _p + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'publisher'), '-w', '1'] + _debug + _subs_rate + args.split()
    child = _spawn(_p, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def py_sub(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('py_scripts', 'simple_sub.py')] + _debug + args.split()
    child = _py_spawn(_s, cmd)
    _expect_listening(child)
    return child

def py_pub(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('py_scripts', 'simple_pub.py')] + _debug + args.split()
    child = _py_spawn(_p, cmd)
    _expect_listening(child)
    return child

def py_late_sub():
    global _s
    _s = _s + 1
    cmd = [os.path.join('py_scripts', 'late_sub.py')] + _debug
    child = _py_spawn(_s, cmd)
    _expect_listening(child)
    return child

def py_retained_pub():
    global _p
    _p = _p + 1
    cmd = [os.path.join('py_scripts', 'retained_pub.py')] + _debug
    child = _py_spawn(_p, cmd)
    _expect_listening(child)
    return child

def py_sub_ks(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('py_scripts', 'simple_sub_ks.py')] + _debug + args.split()
    child = _py_spawn(_s, cmd)
    _expect_listening(child)
    return child

def py_pub_ks(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('py_scripts', 'simple_pub_ks.py')] + _debug + args.split()
    child = _py_spawn(_p, cmd)
    _expect_listening(child)
    return child

def js_sub(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('js_scripts', 'simple_sub.js')] + _debug + args.split()
    child = _js_spawn(_s, cmd)
    _expect_listening(child)
    return child

def js_pub(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('js_scripts', 'simple_pub.js')] + _debug + args.split()
    child = _js_spawn(_p, cmd)
    _expect_listening(child)
    return child

def js_sub_ks(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('js_scripts', 'simple_sub_ks.js')] + _debug + args.split()
    child = _js_spawn(_s, cmd)
    _expect_listening(child)
    return child

def js_pub_ks(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('js_scripts', 'simple_pub_ks.js')] + _debug + args.split()
    child = _js_spawn(_p, cmd)
    _expect_listening(child)
    return child

def tutorial(args=''):
    global _t
    _t = _t + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'tutorial')] + _debug + args.split()
    child = _spawn(_t, cmd)
    _expect_listening(child)
    _expect_linked(child, args)
    return child

def ver(args=''):
    global _v
    _v = _v + 1
    cmd = [os.path.join('build', 'test', 'bin', 'version')] + _debug + args.split()
    child = _spawn(_v, cmd)
    _expect_listening(child)
    return child

def reg(args=''):
    global _r
    _r = _r + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'registry')] + _debug + _subs_rate + args.split()
    child = _spawn(_r, cmd)
    _expect_listening(child)
    return child

def reg_subs(args=''):
    global _rs
    _rs = _rs + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'reg_subs')] + _debug + args.split()
    child = _spawn(_rs, cmd)
    _expect_listening(child)
    return child

def reg_pubs(args=''):
    global _rp
    _rp = _rp + 1
    cmd = [os.path.join('build', 'dist', 'bin', 'reg_pubs'), '-w', '1'] + _debug + args.split()
    child = _spawn(_rp, cmd)
    _expect_listening(child)
    return child

def topic_match(pattern, args=''):
    global _tm
    _tm = _tm + 1
    cmd = [os.path.join('build', 'test', 'bin', 'topic_match')] + _debug + args.split()
    child = _spawn(_tm, cmd)
    _expect([child], [pattern])

def expect_reg_linked(children):
    if not isinstance(children, collections.Sequence):
        children = [children]
    _expect(children, ['is linked to \S+/\d+'])

def mesh_stress(args=''):
    global _ms
    _ms = _ms + 1
    cmd = [os.path.join('build', 'test', 'bin', 'mesh_stress')] + _debug + args.split()
    return _spawn(_ms, cmd)

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
