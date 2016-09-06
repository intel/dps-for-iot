Import('env')

# Core libraries
libenv = env.Clone()
# Additional warning for the core object files
libenv.Append(CFLAGS = ['-Wall', '-Werror', '-Wno-format-extra-args'])
srcs = libenv.Glob('src/*.c')
objs = libenv.StaticObject(srcs)
lib = libenv.StaticLibrary('lib/dps', objs)
shobjs = libenv.SharedObject(srcs)
shlib = libenv.SharedLibrary('lib/dps', shobjs)

# Use SWIG to build the python wrapper
pyenv = libenv.Clone();
pyenv.Append(SWIGFLAGS = ['-python', '-Werror', '-v'],
             SWIGPATH = '#/inc')
pyenv.Append(CPPPATH = '/usr/include/python2.7')
pydps = pyenv.SharedLibrary('lib/pydps', shobjs + ['swig/dps_python.i'])
pyenv.InstallAs('swig/_dps.so', pydps)

# Use SWIG to build the node.js wrapper
nodeenv = libenv.Clone();
nodeenv.Append(SWIGFLAGS = ['-javascript', '-node', '-c++', '-DV8_VERSION=0x04059937', '-Wall', '-Werror', '-v'],
               SWIGPATH = '#/inc')
nodeenv.Append(CPPFLAGS = ['-DBUILDING_NODE_EXTENSION'])
nodeenv.Append(CPPPATH = ['/usr/include/node'])
nodedps = nodeenv.SharedLibrary('lib/nodedps', shobjs + ['swig/dps_node.i'])
nodeenv.InstallAs('swig/dps.node', nodedps)

# Unit tests
testenv = env.Clone()
testenv.Append(LIBS = lib)
testenv.Program('bin/countvec', 'test/countvec.c')
testenv.Program('bin/unified', 'test/unified.c')
testenv.Program('bin/subtree_sim', 'test/subtree_sim.c')
testenv.Program('bin/tree_sim', 'test/tree_sim.c')
testenv.Program('bin/rle_compression', 'test/rle_compression.c')
testenv.Program('bin/topic_match', 'test/topic_match.c')
testenv.Program('bin/rand_sub', 'test/rand_sub.c')
testenv.Program('bin/rand_pub', 'test/rand_pub.c')
testenv.Program('bin/hashtest', 'test/hashtest.c')
testenv.Program('bin/stats', 'test/stats.c')
testenv.Program('bin/pubsub', 'test/pubsub.c')
testenv.Program('bin/coap_mcast_test', 'test/coap_mcast_test.c')
testenv.Program('bin/packtest', 'test/packtest.c')
testenv.Program('bin/nettest', 'test/nettest.c')
testenv.Program('bin/cbortest', 'test/cbortest.c')

# Examples
exampleenv = env.Clone()
exampleenv.Append(LIBS = lib)
exampleenv.Program('bin/publisher', 'examples/publisher.c')
exampleenv.Program('bin/subscriber', 'examples/subscriber.c')


