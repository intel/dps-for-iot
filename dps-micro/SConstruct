import os
import platform

vars = Variables()

# Generic build variables
vars.AddVariables(
    EnumVariable('variant', 'Build variant', default='debug', allowed_values=('debug', 'release'), ignorecase=2),
    ('CC', 'C compiler to use'),
    ('CXX', 'C++ compiler to use'))

# Windows-specific command line variables
if platform.system() == 'Windows':
    vars.AddVariables(
        PathVariable('UV_PATH', 'Path where libuv is installed', 'ext\libuv', PathVariable.PathAccept),
        PathVariable('DEF_FILE', 'Path to external defs for dll', 'dps_shared.def', PathVariable.PathIsFile))

# Linux-specific command line variables
if platform.system() == 'Linux':
    vars.AddVariables(
        BoolVariable('profile', 'Build for profiling?', False),
        BoolVariable('asan', 'Enable address sanitizer?', False),
        BoolVariable('tsan', 'Enable thread sanitizer?', False),
        BoolVariable('ubsan', 'Enable undefined behavior sanitizer?', False),
        BoolVariable('fsan', 'Enable fuzzer sanitizer?', False),
        BoolVariable('cov', 'Enable code coverage?', False))

extEnv = Environment(ENV = os.environ, variables=vars)

env = Environment(
    CPPPATH=['#/include'],
    CPPDEFINES=[],
    variables=vars
)

Help(vars.GenerateHelpText(env))

for key, val in ARGLIST:
    if key.lower() == 'define':
        env['CPPDEFINES'].append(val)

print("Building for " + env['variant'])

# Platform specific configuration

if env['PLATFORM'] == 'win32':

    env.Append(CCFLAGS = ['/J', '/W3', '/WX', '/nologo'])
    env.Append(CCFLAGS = ['/execution-charset:utf-8'])

    if env['variant'] == 'debug':
        env.Append(CCFLAGS = ['/Zi', '/MT', '/Od', '-DDPS_DEBUG'])
        env.Append(LINKFLAGS = ['/DEBUG'])
    else:
        env.Append(CCFLAGS = ['/Gy', '/O2', '/GF', '/MT'])
        env.Append(LINKFLAGS = ['/opt:ref'])

    # Stack-based Buffer Overrun Detection
    env.Append(CCFLAGS = ['/GS'])
    # Compiler settings validation
    env.Append(CCFLAGS = ['/sdl'])

    # Data Execution Prevention
    env.Append(LINKFLAGS = ['/NXCompat'])
    # Image Randomization
    env.Append(LINKFLAGS = ['/DynamicBase'])

    # Windows libs
    env['DPS_LIBS'] = ['ws2_32', 'psapi', 'iphlpapi', 'shell32', 'userenv', 'user32', 'advapi32']

    # Windows target
    env.Append(CPPDEFINES = ['DPS_TARGET=DPS_TARGET_WINDOWS'])

elif env['PLATFORM'] == 'posix':

    # uncomment to test for C90 (with gnu extensions) compatibility
    #env.Append(CCFLAGS = ['-std=gnu90'])

    # Enable address sanitizer
    if env['asan'] == True:
        env.Append(CCFLAGS = ['-fno-omit-frame-pointer', '-fsanitize=address'])
        if 'gcc' in env['CC']:
            env.Append(LIBS = ['asan'])
        elif 'clang' in env['CC']:
            env.Append(LINKFLAGS = ['-fsanitize=address'])
        else:
            print('Unsupported compiler')
            exit();

    # Enable thread sanitizer
    if env['tsan'] == True:
        env.Append(CCFLAGS = ['-fsanitize=thread'])
        if 'gcc' in env['CC']:
            env.Append(LIBS = ['tsan'])
        elif 'clang' in env['CC']:
            env.Append(LINKFLAGS = ['-fsanitize=thread'])
        else:
            print('Unsupported compiler')
            exit();

    # Enable undefined behavior sanitizer
    if env['ubsan'] == True:
        env.Append(CCFLAGS = ['-fsanitize=undefined'])
        if 'gcc' in env['CC']:
            env.Append(LIBS = ['ubsan'])
        elif 'clang' in env['CC']:
            env.Append(LINKFLAGS = ['-fsanitize=undefined'])
        else:
            print('Unsupported compiler')
            exit();

    # Enable fuzzer sanitizer
    if env['fsan'] == True:
        if 'clang' in env['CC']:
            env.Append(CCFLAGS = ['-fsanitize=fuzzer-no-link'])
        else:
            print('Unsupported compiler')
            exit();

    # Enable code coverage
    if env['cov'] == True:
        if 'clang' in env['CC']:
            env.Append(CCFLAGS = ['-fprofile-instr-generate', '-fcoverage-mapping'])
            env.Append(LINKFLAGS = ['-fprofile-instr-generate', '-fcoverage-mapping'])
        else:
            print('Unsupported compiler')
            exit();

    # Stack execution protection:
    env.Append(LINKFLAGS = ['-z', 'noexecstack'])

    # Data relocation and protection (RELRO):
    env.Append(LINKFLAGS = ['-z', 'relro', '-z', 'now'])

    # Stack-based Buffer Overrun Detection:
    env.Append(CCFLAGS = ['-fstack-protector-strong'])

    # Position Independent Execution (PIE)
    env.Append(CCFLAGS = ['-fPIE', '-fPIC'])
    env.Append(LINKFLAGS = ['-pie']) # PIE for executables only

    # Fortify source:
    env.Append(CPPDEFINES = ['_FORTIFY_SOURCE=2'])

    # Format string vulnerabilities
    env.Append(CCFLAGS= ['-Wformat', '-Wformat-security'])

    # gcc option  -mmsse4.2 is to enble generation of popcountq instruction
    env.Append(CCFLAGS = ['-ggdb', '-msse4.2'])

    # Treat warnings as errors
    env.Append(CCFLAGS = ['-Werror'])

    if env['profile'] == True:
        env.Append(CCFLAGS = ['-pg'])
        env.Append(LINKFLAGS = ['-pg'])

    if env['variant'] == 'debug':
        env.Append(CCFLAGS = ['-O', '-DDPS_DEBUG'])
    else:
        env.Append(CCFLAGS = ['-O3', '-DNDEBUG'])

    # Where to find Python.h
    if env['target'] == 'yocto':
        env['PY_CPPPATH'] = [os.getenv('SYSROOT') + '/usr/include/python2.7']
    else:
        env['PY_CPPPATH'] = ['/usr/include/python2.7']
    env['PY_LIBPATH'] = []

    env['DPS_LIBS'] = ['pthread']

    # Check if we need to build libuv
    conf = env.Configure()
    extUV = not conf.CheckLib('uv', symbol='uv_mutex_init_recursive')
    env = conf.Finish()

    # Linux target
    env.Append(CPPDEFINES = ['DPS_TARGET=DPS_TARGET_LINUX'])

else:
    print('Unsupported system')
    exit()

env.Append(LIBPATH=['./ext'])

print(env['CPPDEFINES'])

ext_libs = []


# Build external dependencies
ext_libs.append(SConscript('ext/SConscript.mbedtls', exports=['extEnv']))

version = '0.1.0'

lib_dps = SConscript('SConscript', src_dir='.', variant_dir='build/obj', duplicate=0, exports=['env', 'ext_libs', 'version'])
