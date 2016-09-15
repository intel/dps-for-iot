import platform

# 
# It not clear why but if SWIG cannot be found when the environment is created the
# SWIG builder does not get applied
#
if platform.system() == 'Windows':
    env = Environment(CPPDEFINES=[], CPPPATH=['./inc'], SWIG='c:\swigwin-3.0.10\swig.exe')
else:
    env = Environment(CPPDEFINES=[], CPPPATH=['./inc'])

optimize = False
debug = True
profile = False

for key, val in ARGLIST:
    if key.lower() == 'define':
	    env['CPPDEFINES'].append(val)
    elif (key == 'optimize' and val == 'true'):
        optimize = True
    elif (key == 'profile' and val == 'true'):
        profile = True
    elif (key == 'debug' and val == 'false'):
        debug = False


# Platform specific configuration

if env['PLATFORM'] == 'win32':

    env.Append(CFLAGS = ['/J', '/W2', '/nologo'])
    env.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS'])

    if debug == True:
        env.Append(CFLAGS = ['/Zi', '/MT', '/Od', '-DDPS_DEBUG'])
        env.Append(LINKFLAGS = ['/DEBUG'])
    else:
        env.Append(CFLAGS = ['/Gy', '/O3', '/GF', '/MT'])
        env.Append(LINKFLAGS = ['/opt:ref', '/NODEFAULTLIB:libcmt.lib'])


    # Where to find Python.h
    env['PY_CPPPATH'] = ['c:\python27\include']
    env['PY_LIBPATH'] = ['c:\python27\libs']

    # Where to find libuv
    env.Append(LIBS = ['libuv', 'ws2_32'])
    env.Append(LIBPATH=['c:\Program Files\libuv'])
    env.Append(CPPPATH = 'c:\Program Files\libuv\include')

elif env['PLATFORM'] == 'posix':

    #gcc option  -mmsse4.2 is to enble generation on popcountq instruction
    env.Append(CFLAGS = ['-ggdb', '-msse4.2'])

    if profile == True:
        env.Append(CFLAGS = ['-pg'])
        env.Append(LINKFLAGS = ['-pg'])

    if optimize == True:
        debug = False
        env.Append(CFLAGS = ['-O3', '-DNDEBUG'])

    if debug == True:
        env.Append(CFLAGS = ['-DDPS_DEBUG'])

    # Where to find Python.h
    env['PY_CPPPATH'] = ['/usr/include/python2.7']
    env['PY_LIBPATH'] = []

    # Where to find libuv
    env.Append(LIBS = ['uv'])

else:
    print 'Unsupported system'
    exit()


print env['CPPDEFINES']

SConscript('SConscript', src_dir='.', variant_dir='build', duplicate=0, exports='env')
