import os
import platform

vars = Variables()

# Generic build variables
vars.AddVariables(
    EnumVariable('variant', 'Build variant', default='release', allowed_values=('debug', 'release'), ignorecase=2),
    EnumVariable('transport', 'Transport protocol', default='udp', allowed_values=('udp', 'tcp'), ignorecase=2))

# Windows-specific command line variables
if platform.system() == 'Windows':
    vars.AddVariables(
        PathVariable('UV_PATH', 'Path to libuv', 'C:\Program Files\libuv'),
        PathVariable('PYTHON_PATH', 'Path to Python', 'C:\Python27'),
        PathVariable('SWIG', 'Path to SWIG executable', 'C:\swigwin-3.0.10\swig.exe'),
        PathVariable('DOXYGEN_PATH', 'Path to Doxygen', 'C:\Program Files\Doxygen', PathVariable.PathAccept))

# Linux-specific command line variables
if platform.system() == 'Linux':
    vars.AddVariables(
        BoolVariable('profile', 'Build for profiling?', False),
        BoolVariable('asan', 'Enable address sanitizer?', False))

tools=['default', 'textfile']
# Doxygen is optional
try:
    env = Environment(tools=['doxygen'])
    tools.append('doxygen')
except:
    pass

env = Environment(CPPDEFINES=[], CPPPATH = ['#/inc', '#/ext/tinycrypt/lib/include', '#/ext/safestring/include'], variables=vars, tools=tools)

Help(vars.GenerateHelpText(env))

for key, val in ARGLIST:
    if key.lower() == 'define':
        env['CPPDEFINES'].append(val)

if env['transport'] == 'udp':
    env['USE_UDP'] = 'true'
    env['CPPDEFINES'].append('DPS_USE_UDP')

# Build external dependencies
extEnv = Environment(ENV = os.environ, variables=vars)
ext_libs = SConscript('ext/SConscript', exports=['extEnv'])

# Platform specific configuration

if env['PLATFORM'] == 'win32':

    env.Append(CFLAGS = ['/J', '/W3', '/nologo'])
    env.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS'])

    # We are getting our secure memory and string functions for
    # SafeStringLib so need to disable the Windows supplied versions
    env.Append(CPPDEFINES = ['__STDC_WANT_SECURE_LIB__=0'])

    if env['variant'] == 'debug':
        env.Append(CFLAGS = ['/Zi', '/MT', '/Od', '-DDPS_DEBUG'])
        env.Append(LINKFLAGS = ['/DEBUG'])
    else:
        env.Append(CFLAGS = ['/Gy', '/O2', '/GF', '/MT'])
        env.Append(LINKFLAGS = ['/opt:ref'])


    # Stack-based Buffer Overrun Detection
    env.Append(CFLAGS = ['/GS'])
    # Compiler settings validation
    env.Append(CFLAGS = ['/sdl'])

    # Data Execution Prevention 
    env.Append(LINKFLAGS = ['/NXCompat'])
    # Image Randomization
    env.Append(LINKFLAGS = ['/DynamicBase'])

    # Where to find Python.h
    env['PY_CPPPATH'] = [env['PYTHON_PATH'] + '\include']
    env['PY_LIBPATH'] = [env['PYTHON_PATH'] + '\libs']

    # Where to find libuv and the libraries it needs
    env['UV_LIBS'] = ['libuv', 'ws2_32','iphlpapi']
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

    # Stack execution protection:
    env.Append(LDFLAGS = ['-z noexecstack'])

    # Data relocation and protection (RELRO):
    env.Append(LDLFAGS= ['-z relro', '-z now']) 

    # Stack-based Buffer Overrun Detection:
    env.Append(CFLAGS = ['-fstack-protector-strong'])

    # Position Independent Execution (PIE)
    env.Append(CFLAGS = ['-fPIE', '-fPIC'])
    env.Append(LDFLAGS = ['-pie']) # PIE for executables only

    # Fortify source:
    env.Append(CPPDEIFINES = ['_FORTIFY_SOURCE=2'])

    # Format string vulnerabilities
    env.Append(CFLAGS= ['-Wformat', '-Wformat-security'])
        
    # gcc option  -mmsse4.2 is to enble generation of popcountq instruction
    env.Append(CFLAGS = ['-ggdb', '-msse4.2'])

    # Treat warnings as errors
    env.Append(CFLAGS = ['-Werror'])

    if env['profile'] == True:
        env.Append(CFLAGS = ['-pg'])
        env.Append(LINKFLAGS = ['-pg'])

    if env['variant'] == 'debug':
        env.Append(CFLAGS = ['-DDPS_DEBUG'])
    else:
        env.Append(CFLAGS = ['-O3', '-DNDEBUG'])

    # Where to find Python.h
    env['PY_CPPPATH'] = ['/usr/include/python2.7']
    env['PY_LIBPATH'] = []

    # Where to find libuv and the libraries it needs
    env['UV_LIBS'] = ['uv', 'pthread']

else:
    print 'Unsupported system'
    exit()

env.Append(LIBPATH=['./ext'])

print env['CPPDEFINES']

SConscript('SConscript', src_dir='.', variant_dir='build/obj', duplicate=0, exports=['env', 'ext_libs'])

######################################################################
# Scons to generate the dps_ns3.pc file from dps_ns3.pc.in file
######################################################################
pc_file = 'dps_ns3.pc.in'
pc_vars = {'\@PREFIX\@': env.GetLaunchDir().encode('string_escape'),
           '\@VERSION\@': '0.9',
}
env.Substfile(pc_file, SUBST_DICT = pc_vars)
