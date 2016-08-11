
cflags = ['-ggdb', '-DDPS_DEBUG']

cppdefines = []

for key, val in ARGLIST:
    if key.lower() == 'define':
        cppdefines.append(val)
    if (key == 'optimize' and val == 'true'):
        cflags = ['-O3', '-DNDEBUG']

# Additional warning for the core object files
wflags = ['-Wall', '-Wno-format-extra-args']

env = Environment(CPPDEFINES=cppdefines, CFLAGS=cflags, CPPPATH=['./inc'], LIBS=['uv'])

print env['CPPDEFINES']

objs = env.Object(Glob('src/*.c'), CFLAGS=cflags + wflags)

# Unit tests
env.Program('bin/countvec', env.Object('test/countvec.c') + objs)
env.Program('bin/unified', env.Object('test/unified.c') + objs)
env.Program('bin/subtree_sim', env.Object('test/subtree_sim.c') + objs)
env.Program('bin/tree_sim', env.Object('test/tree_sim.c') + objs)
env.Program('bin/rle_compression', env.Object('test/rle_compression.c') + objs)
env.Program('bin/topic_match', env.Object('test/topic_match.c') + objs)
env.Program('bin/rand_sub', env.Object('test/rand_sub.c') + objs)
env.Program('bin/rand_pub', env.Object('test/rand_pub.c') + objs)
env.Program('bin/hashtest', env.Object('test/hashtest.c') + objs)
env.Program('bin/stats', env.Object('test/stats.c') + objs)
env.Program('bin/pubsub', env.Object('test/pubsub.c') + objs)
env.Program('bin/coap_mcast_test', env.Object('test/coap_mcast_test.c') + objs)
env.Program('bin/packtest', env.Object('test/packtest.c') + objs)
env.Program('bin/nettest', env.Object('test/nettest.c') + objs)
env.Program('bin/cbortest', env.Object('test/cbortest.c') + objs)

# Examples
env.Program('bin/publisher', env.Object('examples/publisher.c') + objs)
env.Program('bin/subscriber', env.Object('examples/subscriber.c') + objs)
