import os
import platform

vars = Variables()
vars.AddVariables(
    BoolVariable('optimize', 'Build for release?', False),
    BoolVariable('profile', 'Build for profiling?', False),
    BoolVariable('debug', 'Build with debugging information?', True),
    BoolVariable('udp', 'Use UDP network layer?', False))
if platform.system() == 'Windows':
    vars.AddVariables(
        PathVariable('UV_PATH', 'Path to libuv', 'C:\Program Files\libuv'),
        PathVariable('PYTHON_PATH', 'Path to Python', 'C:\Python27'),
        PathVariable('SWIG', 'Path to SWIG executable', 'C:\swigwin-3.0.10\swig.exe'),
        PathVariable('DOXYGEN_PATH', 'Path to Doxygen', 'C:\Program Files\Doxygen', PathVariable.PathAccept))
if platform.system() == 'Linux':
    vars.AddVariables(
        BoolVariable('asan', 'Enable address sanitizer?', False))

tools=['default', 'textfile']
# Doxygen is optional
try:
    env = Environment(tools=['doxygen'])
    tools.append('doxygen')
except:
    pass

env = Environment(CPPDEFINES=[], CPPPATH = ['#/inc', '#/ext/tinycrypt/lib/include'], variables=vars, tools=tools)

Help(vars.GenerateHelpText(env))

for key, val in ARGLIST:
    if key.lower() == 'define':
        env['CPPDEFINES'].append(val)

if env['udp'] == True:
    env['USE_UDP'] = 'true'
    env['CPPDEFINES'].append('DPS_USE_UDP')

# Dependencies
depenv = Environment(ENV = os.environ)
tcgit = depenv.Command("ext/tinycrypt/.git", None, "git clone https://github.com/01org/tinycrypt.git ext/tinycrypt")
ext_deps = depenv.Command("ext/tinycrypt/lib/libtinycrypt.a", tcgit, "cd ext/tinycrypt && make")

# Platform specific configuration

if env['PLATFORM'] == 'win32':

    env.Append(CFLAGS = ['/J', '/W3', '/nologo'])
    env.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS'])

    if env['debug'] == True:
        env.Append(CFLAGS = ['/Zi', '/MT', '/Od', '-DDPS_DEBUG'])
        env.Append(LINKFLAGS = ['/DEBUG'])
    else:
        env.Append(CFLAGS = ['/Gy', '/O3', '/GF', '/MT'])
        env.Append(LINKFLAGS = ['/opt:ref', '/NODEFAULTLIB:libcmt.lib'])

    # Where to find Python.h
    env['PY_CPPPATH'] = [env['PYTHON_PATH'] + '\include']
    env['PY_LIBPATH'] = [env['PYTHON_PATH'] + '\libs']

    # Where to find libuv
    env['UV_LIBS'] = ['libuv', 'ws2_32','iphlpapi', 'libtinycrypt']
    env.Append(LIBPATH=[env['UV_PATH']])
    env.Append(CPPPATH=env['UV_PATH'] + '\include')

    # Doxygen needs to be added to default path if available
    if env['DOXYGEN_PATH']:
        env.PrependENVPath('PATH', env['DOXYGEN_PATH'] + '/bin')

elif env['PLATFORM'] == 'posix':

    # Enable address sanitizer
    if env['asan'] == True:
        env.Append(CFLAGS = ['-fno-omit-frame-pointer', '-fsanitize=address'])
        env.Append(LIBS = ['asan'])

    #gcc option  -mmsse4.2 is to enble generation on popcountq instruction
    env.Append(CFLAGS = ['-ggdb', '-msse4.2'])
    env.Append(CFLAGS = ['-Werror'])

    if env['profile'] == True:
        env.Append(CFLAGS = ['-pg'])
        env.Append(LINKFLAGS = ['-pg'])

    if env['optimize'] == True:
        env['debug'] = False
        env.Append(CFLAGS = ['-O3', '-DNDEBUG'])

    if env['debug'] == True:
        env.Append(CFLAGS = ['-DDPS_DEBUG'])

    # Where to find Python.h
    env['PY_CPPPATH'] = ['/usr/include/python2.7']
    env['PY_LIBPATH'] = []

    env.Append(LIBPATH=['#/ext/tinycrypt/lib'])

    # Where to find libuv
    env['UV_LIBS'] = ['uv', 'pthread', 'tinycrypt']

else:
    print 'Unsupported system'
    exit()


print env['CPPDEFINES']

SConscript('SConscript', src_dir='.', variant_dir='build/obj', duplicate=0, exports=['env', 'ext_deps'])

######################################################################
# Scons to generate the dps_ns3.pc file from dps_ns3.pc.in file
######################################################################
pc_file = 'dps_ns3.pc.in'
pc_vars = {'\@PREFIX\@': env.GetLaunchDir().encode('string_escape'),
           '\@VERSION\@': '0.9',
}
env.Substfile(pc_file, SUBST_DICT = pc_vars)
