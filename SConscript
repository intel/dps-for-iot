Import('env')

platform = env['PLATFORM']

# Additional warning for the lib object files

# Core libraries
libenv = env.Clone()

# Additional warnings for the core object files
if platform == 'win32':
    libenv.Append(CFLAGS = ['/W3']);
elif platform == 'posix':
    libenv.Append(CFLAGS = ['-Wall', '-Werror', '-Wno-format-extra-args'])

srcs = libenv.Glob('src/*.c')
objs = libenv.Object(srcs)
lib = libenv.Library('lib/dps', objs)
# Windows doesn't distinguish between static and dynamic obj files
shobjs = objs if platform == 'win32' else libenv.SharedObject(srcs)
shlib = libenv.SharedLibrary('lib/dps_shared', shobjs)

# Using SWIG to build the python wrapper
pyenv = libenv.Clone()
pyenv.Append(LIBPATH = env['PY_LIBPATH'])
pyenv.Append(CPPPATH = env['PY_CPPPATH'])
# On Widows Python has a special .pyd suffix for module libraries
if platform == 'win32':  pyenv['SHLIBSUFFIX'] = '.pyd'
pyenv.Append(SWIGFLAGS = ['-python', '-Werror', '-v'], SWIGPATH = '#/inc')
# Build python module library
pyenv.SharedLibrary('py/_dps', shobjs + ['swig/dps_python.i'])
pyenv.InstallAs('./py', './swig')

# Use SWIG to build the node.js wrapper
if platform == 'posix':
    nodeenv = libenv.Clone();
    nodeenv.Append(SWIGFLAGS = ['-javascript', '-node', '-c++', '-DV8_VERSION=0x04059937', '-Wall', '-Werror', '-v'], SWIGPATH = '#/inc')
    nodeenv.Append(CPPFLAGS = ['-DBUILDING_NODE_EXTENSION'])
    nodeenv.Append(CPPPATH = ['/usr/include/node'])
    nodedps = nodeenv.SharedLibrary('lib/nodedps', shobjs + ['swig/dps_node.i'])
    nodeenv.InstallAs('swig/dps.node', nodedps)

# Unit tests
testenv = env.Clone()
testenv.Append(LIBS = lib)
testenv.Program('bin/countvec', 'test/countvec.c')
testenv.Program('bin/unified', 'test/unified.c')
testenv.Program('bin/rle_compression', 'test/rle_compression.c')
testenv.Program('bin/topic_match', 'test/topic_match.c')
testenv.Program('bin/rand_sub', 'test/rand_sub.c')
testenv.Program('bin/rand_pub', 'test/rand_pub.c')
testenv.Program('bin/hashtest', 'test/hashtest.c')
testenv.Program('bin/stats', 'test/stats.c')
testenv.Program('bin/pubsub', 'test/pubsub.c')
testenv.Program('bin/packtest', 'test/packtest.c')
testenv.Program('bin/nettest', 'test/nettest.c')
testenv.Program('bin/cbortest', 'test/cbortest.c')

# Platform-specific test cases
if platform == 'posix':
    testenv.Program('bin/coap_mcast_test', 'test/coap_mcast_test.c')
    testenv.Program('bin/subtree_sim', 'test/subtree_sim.c')
    testenv.Program('bin/tree_sim', 'test/tree_sim.c')


# Examples
exampleenv = env.Clone()
exampleenv.Append(LIBS = lib)
exampleenv.Program('bin/publisher', 'examples/publisher.c')
exampleenv.Program('bin/subscriber', 'examples/subscriber.c')


