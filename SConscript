Import('env')

# Additional warning for the core object files

cflags = env['CFLAGS'] + ['-Wall', '-Werror', '-Wno-format-extra-args']

env.StaticLibrary('lib/dps', Glob('src/*.c'), LIBS=[], CFLAGS=cflags)
env.SharedLibrary('lib/dps', Glob('src/*.c'), LIBS=[], CFLAGS=cflags)

# Unit tests
env.Program('bin/countvec', env.Object('test/countvec.c'))
env.Program('bin/unified', env.Object('test/unified.c'))
env.Program('bin/subtree_sim', env.Object('test/subtree_sim.c'))
env.Program('bin/tree_sim', env.Object('test/tree_sim.c'))
env.Program('bin/rle_compression', env.Object('test/rle_compression.c'))
env.Program('bin/topic_match', env.Object('test/topic_match.c'))
env.Program('bin/rand_sub', env.Object('test/rand_sub.c'))
env.Program('bin/rand_pub', env.Object('test/rand_pub.c'))
env.Program('bin/hashtest', env.Object('test/hashtest.c'))
env.Program('bin/stats', env.Object('test/stats.c'))
env.Program('bin/pubsub', env.Object('test/pubsub.c'))
env.Program('bin/coap_mcast_test', env.Object('test/coap_mcast_test.c'))
env.Program('bin/packtest', env.Object('test/packtest.c'))
env.Program('bin/nettest', env.Object('test/nettest.c'))
env.Program('bin/cbortest', env.Object('test/cbortest.c'))

# Examples
env.Program('bin/publisher', env.Object('examples/publisher.c'))
env.Program('bin/subscriber', env.Object('examples/subscriber.c'))
