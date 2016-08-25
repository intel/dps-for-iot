cflags = ['-ggdb', '-DDPS_DEBUG']

cppdefines = []

for key, val in ARGLIST:
    if key.lower() == 'define':
        cppdefines.append(val)
    if (key == 'optimize' and val == 'true'):
        cflags = ['-O3', '-DNDEBUG']

env = Environment(CPPDEFINES=cppdefines, CFLAGS=cflags, CPPPATH=['./inc'], LIBS=['uv', 'dps'], LIBPATH=['./build/lib'])

print env['CPPDEFINES']

SConscript('SConscript', src_dir='.', variant_dir='build', duplicate=0, exports='env')
#SConscript('SConscript', exports=['env', 'cflags'])
