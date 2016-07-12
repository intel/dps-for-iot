

#cflags = ['-O3']
cflags = ['-ggdb', '-DDPS_DEBUG']

objs = Object(Glob('src/*.c'), CPPPATH=['./inc'], CFLAGS=cflags)

# Unit tests
Program('bin/rand_pubsub', Object('test/rand_pubsub.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/whiten_unit', Object('test/whiten_unit.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/tree_sim', Object('test/tree_sim.c', CFLAGS=cflags))
Program('bin/rle_compression', Object('test/rle_compression.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/topic_match', Object('test/topic_match.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/multi_subs', Object('test/multi_subs.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/rand_sub', Object('test/rand_sub.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/rand_pub', Object('test/rand_pub.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/hashtest', Object('test/hashtest.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/stats', Object('test/stats.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/pubsub', Object('test/pubsub.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/coap_mcast_test', Object('test/coap_mcast_test.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/packtest', Object('test/packtest.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/nettest', Object('test/nettest.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/cbortest', Object('test/cbortest.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])

# Examples
Program('bin/publisher', Object('examples/publisher.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
Program('bin/subscriber', Object('examples/subscriber.c', CFLAGS=cflags, CPPPATH=['./inc']) + objs, LIBS=['uv'])
