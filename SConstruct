import os
import platform

AddOption('--tool', action='append', dest='tools', help='Add tool to the environment')

vars = Variables()

bindings = Split('python nodejs go')

# Generic build variables
vars.AddVariables(
    BoolVariable('profile', 'Build for profiling?', False),
    BoolVariable('asan', 'Enable address sanitizer?', False),
    BoolVariable('tsan', 'Enable thread sanitizer?', False),
    BoolVariable('ubsan', 'Enable undefined behavior sanitizer?', False),
    BoolVariable('fsan', 'Enable fuzzer sanitizer?', False),
    BoolVariable('cov', 'Enable code coverage?', False),
    EnumVariable('variant', 'Build variant', default='release', allowed_values=('debug', 'release'), ignorecase=2),
    EnumVariable('transport', 'Transport protocol', default='udp', allowed_values=('udp', 'tcp', 'dtls', 'pipe', 'fuzzer'), ignorecase=2),
    EnumVariable('target', 'Build target', default='local', allowed_values=('local', 'yocto'), ignorecase=2),
    ListVariable('bindings', 'Bindings to build', bindings, bindings),
    PathVariable('application', 'Application to build', '', PathVariable.PathAccept),
    ('CC', 'C compiler to use'),
    ('CXX', 'C++ compiler to use'))

# Windows-specific command line variables
if platform.system() == 'Windows':
    vars.AddVariables(
        PathVariable('DOXYGEN_PATH', 'Path to Doxygen', 'C:\Program Files\Doxygen', PathVariable.PathAccept),
        PathVariable('GIT_PATH', 'Path where git is installed', 'C:\Program Files\Git', PathVariable.PathAccept),
        PathVariable('PYTHON_PATH', 'Path to Python', 'C:\Python27', PathVariable.PathAccept),
        PathVariable('UV_PATH', 'Path where libuv is installed', 'ext\libuv', PathVariable.PathAccept),
        PathVariable('SWIG', 'Path to SWIG executable', 'C:\swigwin-3.0.10\swig.exe', PathVariable.PathAccept),
        PathVariable('NASM_PATH', 'Path to where NASM is installed', 'C:\Program Files\NASM', PathVariable.PathAccept),
        PathVariable('DEF_FILE', 'Path to external defs for dll', 'dps_shared.def', PathVariable.PathIsFile))

tools = GetOption('tools')
if tools == None:
    tools = ['default']
tools.extend(['swig', 'textfile', DPS])

# Doxygen is optional
try:
    env = Environment(tools=['doxygen'])
    tools.append('doxygen')
except:
    pass

env = Environment(
    # os.environ must be imported for the mingw tool to find (and succesfully run) the compiler
    ENV = os.environ,
    variables = vars,
    tools = tools,
)

Help(vars.GenerateHelpText(env))

for key, val in ARGLIST:
    if key.lower() == 'define':
        env.Append(CPPDEFINES = [val])

# Unpack bindings into individually testable booleans
for b in bindings:
    env[b] = b in env['bindings']

if env['transport'] == 'udp':
    env['USE_UDP'] = 'true'
    env.Append(CPPDEFINES = ['DPS_USE_UDP'])
elif env['transport'] == 'tcp':
    env['USE_TCP'] = 'true'
    env.Append(CPPDEFINES = ['DPS_USE_TCP'])
elif env['transport'] == 'dtls':
    env['USE_DTLS'] = 'true'
    env.Append(CPPDEFINES = ['DPS_USE_DTLS'])
elif env['transport'] == 'pipe':
    env['USE_PIPE'] = 'true'
    env.Append(CPPDEFINES = ['DPS_USE_PIPE'])

print("Building for " + env['variant'])

# Platform specific configuration

if env['PLATFORM'] == 'win32':
    env.AppendENVPath('PATH', env['GIT_PATH'] + '\cmd')
    env.AppendENVPath('PATH', env['NASM_PATH'])

    env.Append(CPPDEFINES = ['WIN32_LEAN_AND_MEAN', '_WIN32_WINNT=0x0600'])
    # We are getting our secure memory and string functions from
    # SafeStringLib so need to disable the Windows supplied versions
    env.Append(CPPDEFINES = ['__STDC_WANT_SECURE_LIB__=0', '_STRALIGN_USE_SECURE_CRT=0', '_CRT_SECURE_NO_WARNINGS'])

    # Where to find Python.h
    env['PY_CPPPATH'] = [env['PYTHON_PATH'] + '\include']
    env['PY_LIBPATH'] = [env['PYTHON_PATH'] + '\libs']

    env['DPS_LIBS'] = ['ws2_32', 'psapi', 'iphlpapi', 'shell32', 'userenv', 'user32', 'advapi32']

    # Check if we need to build libuv
    extUV = env['UV_PATH'] == 'ext\libuv'
    if not extUV:
        env.Append(DPS_LIBS=['libuv'])
        env.Append(CPPPATH=[env['UV_PATH'] + '\include'])
        env.Append(LIBPATH=[env['UV_PATH']])

    # Doxygen needs to be added to default path if available
    if env['DOXYGEN_PATH']:
        env.PrependENVPath('PATH', env['DOXYGEN_PATH'] + '/bin')

elif env['PLATFORM'] == 'posix':
    # Where to find Python.h
    if env['target'] == 'yocto':
        env['PY_CPPPATH'] = [os.getenv('SYSROOT') + '/usr/include/python2.7']
    else:
        py_cpppath = os.popen('python-config --includes').read().split()
        env['PY_CPPPATH'] = map(lambda inc: inc[2:], py_cpppath)
    env['PY_LIBPATH'] = []

    env['DPS_LIBS'] = ['pthread']

    # Check if we need to build libuv
    conf = env.Configure()
    extUV = not conf.CheckLib('uv', symbol='uv_mutex_init_recursive')
    env = conf.Finish()

else:
    print('Unsupported system')
    exit()

if env['CC'] == 'cl':
    env.Append(CCFLAGS = ['/J', '/execution-charset:utf-8', '/Zc:wchar_t'])

    if env['variant'] == 'debug':
        env.Append(CCFLAGS = ['/Zi', '/MT', '/Od', '-DDPS_DEBUG'])
        env.Append(LINKFLAGS = ['/DEBUG'])
    else:
        env.Append(CCFLAGS = ['/Gy', '/O2', '/GF', '/GL', '/MT'])
        env.Append(ARFLAGS = ['/LTCG'])
        env.Append(LINKFLAGS = ['/opt:ref', '/LTCG'])

    # Stack-based Buffer Overrun Detection
    env.Append(CCFLAGS = ['/GS'])

    # Data Execution Prevention
    env.Append(LINKFLAGS = ['/NXCompat'])
    # Image Randomization
    env.Append(LINKFLAGS = ['/DynamicBase'])

else:
    # uncomment to test for C90 (with gnu extensions) compatibility
    #env.Append(CCFLAGS = ['-std=gnu90'])

    if 'clang' in env['CC']:
        # clang complains about the CBOR_SIZEOF_UINT() macro when the arg is a uint8_t
        env.Append(CCFLAGS = ['-Wno-tautological-constant-out-of-range-compare'])

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

    env.Append(CPPDEFINES = ['_FILE_OFFSET_BITS=64'])
    env.Append(CCFLAGS = ['-fPIC', '-fvisibility=hidden'])

    # Fortify source:
    env.Append(CPPDEFINES = ['_FORTIFY_SOURCE=2'])

    env.Append(CCFLAGS = ['-ggdb', '-march=native'])

    if env['profile'] == True:
        env.Append(CCFLAGS = ['-pg'])
        env.Append(LINKFLAGS = ['-pg'])

    if env['variant'] == 'debug':
        env.Append(CCFLAGS = ['-O', '-DDPS_DEBUG'])
    else:
        env.Append(CCFLAGS = ['-O3', '-DNDEBUG'])

if env['PLATFORM'] == 'win32' and 'gcc' in env['CC']:
    env.Append(CPPDEFINES = ['__USE_MINGW_ANSI_STDIO=1'])

    # Data Execution Prevention
    env.Append(LINKFLAGS = ['-Wl,--nxcompat'])

    # Image Randomization
    env.Append(LINKFLAGS = ['-Wl,--dynamicbase'])

elif env['PLATFORM'] == 'posix':
    # Stack-based Buffer Overrun Detection:
    env.Append(CCFLAGS = ['-fstack-protector-strong'])

    env.Append(CCFLAGS = ['-fPIE'])
    env.Append(LINKFLAGS = ['-pie']) # PIE for executables only

    # Stack execution protection:
    env.Append(LINKFLAGS = ['-z', 'noexecstack'])

    # Data relocation and protection (RELRO):
    env.Append(LINKFLAGS = ['-z', 'relro', '-z', 'now'])

env.Append(LIBPATH=['./ext'])

print(env['CPPDEFINES'])

if env['target'] == 'yocto':
    env_options = ["SYSROOT", "CC", "AR", "ARFLAGS", "CCFLAGS", "CFLAGS", "CXX", "CXXFLAGS", "LINKFLAGS", "STRIP", "PKG_CONFIG", "CHRPATH", "LD", "TAR"]
    for i in env_options:
        if os.environ.has_key(i):
            if i in ("CFLAGS", "CCFLAGS", "LINKFLAGS"):
                env.Replace(**{i: Split(os.getenv(i))})
            else:
                env.Replace(**{i: os.getenv(i)})
    env.PrependENVPath('PATH', os.getenv('PATH'))
    env.PrependENVPath('LDFLAGS', os.getenv('LDFLAGS'))

ext_objs = []
ext_shobjs = []

# Build external dependencies
objs, shobjs = env.SConscript('ext/SConscript.mbedtls', exports=['env'])
ext_objs.append(objs)
ext_shobjs.append(shobjs)
objs, shobjs = env.SConscript('ext/SConscript.safestring', exports=['env'])
ext_objs.append(objs)
ext_shobjs.append(shobjs)
if extUV:
    objs, shobjs = env.SConscript('ext/SConscript.libuv', exports=['env'])
    ext_objs.append(objs)
    ext_shobjs.append(shobjs)
objs, shobjs = env.SConscript('ext/SConscript.intel-ipsec-mb', exports=['env'])
ext_objs.append(objs)
ext_shobjs.append(shobjs)

version = '0.9.0'

# Build DPS
lib_dps = env.SConscript('SConscript', src_dir='.', variant_dir='build/obj', duplicate=0, exports=['env', 'ext_objs', 'ext_shobjs', 'extUV', 'version'])

# Build any user applications
appDir = env['application']
if appDir != '':
    print('Building application in ', appDir)
    env.Default(appDir)
    env.SConscript(appDir + '/SConscript', variant_dir=appDir + '/build/obj', duplicate=0, exports=['env', 'lib_dps'])

######################################################################
# Scons to generate the dps_ns3.pc file from dps_ns3.pc.in file
######################################################################
pc_file = 'dps_ns3.pc.in'
pc_vars = {'\@PREFIX\@': env.GetLaunchDir().encode('unicode_escape'),
           '\@VERSION\@': version,
}
env.Substfile(pc_file, SUBST_DICT = pc_vars)
