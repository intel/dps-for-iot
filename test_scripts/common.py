#!/usr/bin/python

import argparse
import collections
import copy
import os
import pexpect
from pexpect import popen_spawn
import re
import signal
import shutil
from subprocess import check_output
import sys

os.environ['USE_DTLS'] = '0'
try:
    if os.environ['TRANSPORT'] == 'dtls':
        os.environ['USE_DTLS'] = '1'
except KeyError:
    pass

os.environ['PYTHONPATH'] = os.path.join('build', 'dist', 'py')
os.environ['NODE_PATH'] = os.path.join('build', 'dist', 'js')
os.environ['LSAN_OPTIONS'] = 'suppressions={}/asan.supp'.format(os.getcwd())

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
if os.environ['USE_DTLS'] == '1':
    _subs_rate = ['-r', '800']
    _pub_wait = ['-w', '4']
else:
    _subs_rate = ['-r', '100']
    _pub_wait = ['-w', '1']

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

def _spawn_env():
    spawn_env = os.environ.copy()
    if 'ASAN' in os.environ and os.environ['ASAN'] == 'yes':
        match = re.search('libasan.*', check_output('ldconfig -p', shell=True))
        libasan = match.group(0).split()[-1]
        spawn_env.update({'LD_PRELOAD': libasan})
    return spawn_env

def _spawn_helper(n, cmd, interpreter=[]):
    global _children, _logs
    name = os.path.basename(cmd[0])
    log_name = 'out/{}{}.log'.format(name, n)
    log = open(log_name, 'wb')
    log.write('=============================\n{}{} {}\n'.format(name, n, ' '.join(cmd[1:])).encode())
    log.write('=============================\n'.encode())
    child = popen_spawn.PopenSpawn(interpreter + cmd, env=_spawn_env(), logfile=log)
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
    _expect([child], ['is listening on ([0-9A-Za-z.:%_\-/\\[\]]+){}'.format(child.linesep)])
    child.port = child.match.group(1)
    # Rewrite the any address to the loopback address
    m = re.match('(.*)(:[0-9]+)', child.port)
    if m != None:
        if m.group(1) == '[::]':
            child.port = '[::1]' + m.group(2)
        elif m.group(1) == '0.0.0.0':
            child.port = '127.0.0.1' + m.group(2)

def _expect_linked(child, args):
    ports = []
    prev = ''
    for curr in args.split():
        if prev == '-p':
            ports.append(curr)
        prev = curr
    while len(ports):
        _expect([child], ['is linked to ([0-9A-Za-z.:%_\-/\\[\]]+){}'.format(child.linesep)])
        # The loopback address may have been resolved to either the IPv4 or IPv6 variant
        addr = child.match.group(1).decode()
        try:
            ports.remove(addr)
        except ValueError:
            m = re.match('(.*)(:[0-9]+)', addr)
            if m != None:
                if m.group(1) == '[::1]':
                    addr = '127.0.0.1' + m.group(2)
                elif m.group(1) == '127.0.0.1':
                    addr = '[::1]' + m.group(2)
            ports.remove(addr)

def expect_linked(child, ports):
    if isinstance(ports, basestring) or not isinstance(ports, collections.Sequence):
        ports = [ports]
    _expect_linked(child, ('-p {} ' * len(ports)).format(*ports))

def _expect_pub(children, topics, allow_error=False, timeout=-1, signers=None):
    for child in children:
        patterns = []
        for topic in topics:
            patterns.append('pub {}'.format(' \| '.join(topic.split())))
        patterns = ['(' + '|'.join(patterns) + '){}'.format(child.linesep)] * len(topics)
        while len(patterns):
            if not allow_error:
                if signers != None:
                    i = child.expect(['ERROR'] + ['Pub [0-9a-f-]+\([0-9]+\) \[(.*)\] matches:'], timeout=timeout)
                    if i == 0:
                        raise RuntimeError('ERROR')
                    signers.append(child.match.group(1).decode())
                i = child.expect(['ERROR'] + patterns, timeout=timeout)
                if i == 0:
                    raise RuntimeError('ERROR')
            else:
                if signers != None:
                    child.expect(['Pub [0-9a-f-]+\([0-9]+\) \[(.*)\] matches:'], timeout=timeout)
                    signers.append(child.match.group(1).decode())
                child.expect(patterns, timeout=timeout)
            patterns.remove(child.match.re.pattern.decode())

def _expect_ack(children, allow_error=False, timeout=-1, signers=None):
    linesep = (children[0] if children else None).linesep
    if signers != None:
        pattern = ['Ack for pub UUID [0-9a-f-]+\([0-9]+\) \[(.*)\]{}'.format(linesep)]
    else:
        pattern = ['Ack for pub']
    if not allow_error:
        pattern.append('ERROR')
    for child in children:
        i = child.expect(pattern, timeout)
        if i != 0:
            raise RuntimeError(pattern[i])
        if signers != None:
            signers.append(child.match.group(1).decode())

def cleanup():
    global _children
    for child in _children:
        if sys.platform == 'win32':
            child.kill(signal.SIGBREAK)
        else:
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
    cmd = [os.path.join('build', 'dist', 'bin', 'publisher')] + _debug + _subs_rate + _pub_wait + args.split()
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

def go_sub(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('build', 'dist', 'go', 'bin', 'simple_sub')] + _debug + args.split()
    child = _spawn(_s, cmd)
    _expect_listening(child)
    return child

def go_pub(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('build', 'dist', 'go', 'bin', 'simple_pub')] + _debug + args.split()
    child = _spawn(_p, cmd)
    _expect_listening(child)
    return child

def go_sub_ks(args=''):
    global _s
    _s = _s + 1
    cmd = [os.path.join('build', 'dist', 'go', 'bin', 'simple_sub_ks')] + _debug + args.split()
    child = _spawn(_s, cmd)
    _expect_listening(child)
    return child

def go_pub_ks(args=''):
    global _p
    _p = _p + 1
    cmd = [os.path.join('build', 'dist', 'go', 'bin', 'simple_pub_ks')] + _debug + args.split()
    child = _spawn(_p, cmd)
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
    cmd = [os.path.join('build', 'dist', 'bin', 'reg_pubs')] + _debug + _pub_wait + args.split()
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
    _expect(children, ['is linked to [0-9A-Za-z.:%_\-/\\[\]]+'])

def mesh_stress(args=''):
    global _ms
    _ms = _ms + 1
    cmd = [os.path.join('build', 'test', 'bin', 'mesh_stress')] + _debug + args.split()
    return _spawn(_ms, cmd)

def link(child, ports):
    if isinstance(ports, basestring) or not isinstance(ports, collections.Sequence):
        ports = [ports]
    child.sendline(('-p {} ' * len(ports)).format(*ports))

def expect(children, pattern, allow_error=False, timeout=-1):
    if not isinstance(children, collections.Sequence):
        children = [children]
    if isinstance(pattern, str):
        pattern = [pattern]
    _expect(children, pattern, allow_error, timeout)

def expect_pub_received(children, topic, allow_error=False, timeout=-1, signers=None):
    if not isinstance(children, collections.Sequence):
        children = [children]
    if isinstance(topic, str):
        topic = [topic]
    _expect_pub(children, topic, allow_error, timeout, signers)

def expect_ack_received(children, allow_error=False, timeout=-1, signers=None):
    if not isinstance(children, collections.Sequence):
        children = [children]
    _expect_ack(children, allow_error, timeout, signers)

def expect_pub_not_received(children, topic, allow_error=False):
    try:
        expect_pub_received(children, topic, allow_error, 1)
    except pexpect.TIMEOUT:
        return
    raise RuntimeError(topic)

def expect_error(children, error):
    expect(children, 'ERROR.*{}'.format(error), allow_error=True)

reset_logs()
