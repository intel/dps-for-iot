Import('env')

platform = env['PLATFORM']

# Additional warning for the lib object files

# Core libraries
libenv = env.Clone()

# Additional warnings for the core object files
if platform == 'win32':
    libenv.Append(CFLAGS = ['/W3']);
    libenv.Append(LIBS = env['UV_LIBS'])
elif platform == 'posix':
    libenv.Append(CFLAGS = ['-Wall', '-Wno-format-extra-args'])

hdrs = libenv.Glob('#/inc/dps/*.h')
libenv.Install('#/build/dist/inc/dps', hdrs)

srcs = ['src/bitvec.c',
        'src/cbor.c',
        'src/coap.c',
        'src/dps.c',
        'src/dbg.c',
        'src/err.c',
        'src/event.c',
        'src/history.c',
        'src/synchronous.c',
        'src/uuid.c',
        'src/murmurhash3.c',
        'src/netmcast.c',
        'src/network.c',
        'src/registration.c',
        'src/topics.c',
        'src/uv_extra.c']

if env['udp'] == True:
    srcs.append('src/udp/network.c')
else:
    srcs.append('src/tcp/network.c')

objs = libenv.Object(srcs)
lib = libenv.Library('lib/dps', objs)
libenv.Install('#/build/dist/lib', lib)
# Windows doesn't distinguish between static and dynamic obj files
shobjs = objs if platform == 'win32' else libenv.SharedObject(srcs)
shlib = libenv.SharedLibrary('lib/dps_shared', shobjs)
libenv.Install('#/build/dist/lib', shlib)

ns3srcs = ['src/bitvec.c',
           'src/cbor.c',
           'src/coap.c',
           'src/dps.c',
           'src/err.c',
           'src/history.c',
           'src/uuid.c',
           'src/murmurhash3.c',
           'src/topics.c']

if platform == 'posix':
    ns3shobjs = libenv.SharedObject(ns3srcs)
    ns3shlib = libenv.SharedLibrary('lib/dps_ns3', ns3shobjs)
    libenv.Install('#/build/dist/lib', ns3shlib)

# Using SWIG to build the python wrapper
pyenv = libenv.Clone()
pyenv.Append(LIBPATH = env['PY_LIBPATH'])
pyenv.Append(CPPPATH = env['PY_CPPPATH'])
pyenv.Append(LIBS = [lib, env['UV_LIBS']])
# Python has platform specific naming conventions
if platform == 'win32':
    pyenv['SHLIBSUFFIX'] = '.pyd'
else:
    pyenv['SHLIBPREFIX'] = '_'
pyenv.Append(SWIGFLAGS = ['-python', '-Werror', '-v'], SWIGPATH = '#/inc')
# Build python module library
pylib = pyenv.SharedLibrary('./py/dps', shobjs + ['swig/dps_python.i'])
pyenv.Install('#/build/dist/py', pylib)
pyenv.InstallAs('#/build/dist/py/dps.py', './swig/dps.py')

# Use SWIG to build the node.js wrapper
if platform == '!!posix':
    nodeenv = libenv.Clone();
    nodeenv.Append(SWIGFLAGS = ['-javascript', '-node', '-c++', '-DV8_VERSION=0x04059937', '-Wall', '-Werror', '-v'], SWIGPATH = '#/inc')
    nodeenv.Append(CPPFLAGS = ['-DBUILDING_NODE_EXTENSION', '-std=c++11'])
    nodeenv.Append(CPPPATH = ['/usr/include/node'])
    nodedps = nodeenv.SharedLibrary('lib/nodedps', shobjs + ['swig/dps_node.i'])
    nodeenv.InstallAs('#/build/dist/js/dps.node', nodedps)

# Unit tests
testenv = env.Clone()
testenv.Append(CPPPATH = ['src'])
testenv.Append(LIBS = [lib, env['UV_LIBS']])
testenv.Program('bin/hist_unit', 'test/hist_unit.c')
testenv.Program('bin/countvec', 'test/countvec.c')
testenv.Program('bin/rle_compression', 'test/rle_compression.c')
testenv.Program('bin/topic_match', 'test/topic_match.c')
testenv.Program('bin/hashtest', 'test/hashtest.c')
testenv.Program('bin/stats', 'test/stats.c')
testenv.Program('bin/pubsub', 'test/pubsub.c')
testenv.Program('bin/packtest', 'test/packtest.c')
testenv.Program('bin/cbortest', 'test/cbortest.c')

# Platform-specific test cases
if platform == 'posix':
    testenv.Program('bin/coap_mcast_test', 'test/coap_mcast_test.c')
    testenv.Program('bin/subtree_sim', 'test/subtree_sim.c')
    testenv.Program('bin/tree_sim', 'test/tree_sim.c')


# Examples
exampleenv = env.Clone()
exampleenv.Append(LIBS = [lib, env['UV_LIBS']])
exampleprogs = [exampleenv.Program('registry', 'examples/registry.c'),
                exampleenv.Program('reg_subs', 'examples/reg_subs.c'),
                exampleenv.Program('reg_pubs', 'examples/reg_pubs.c'),
                exampleenv.Program('publisher', 'examples/publisher.c'),
                exampleenv.Program('pub_many', 'examples/pub_many.c'),
                exampleenv.Program('subscriber', 'examples/subscriber.c')]
exampleenv.Install('#/build/dist/bin', exampleprogs)

# Documentation
try:
    libenv.Doxygen('doc/Doxyfile')
except:
    # Doxygen may not be installed
    pass
