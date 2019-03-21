import os
import re
import string
Import(['env', 'ext_objs', 'ext_shobjs', 'extUV', 'version'])

# Additional warning for the these files
commonenv = env.Clone()
if commonenv['CC'] == 'cl':
    commonenv.Append(CCFLAGS = ['/W3', '/WX'])
    # Compiler settings validation
    commonenv.Append(CCFLAGS = ['/sdl'])
else:
    commonenv.Append(CCFLAGS = ['-Werror', '-Wall', '-Wextra', '-Wformat-security'])
    commonenv.Append(CCFLAGS = ['-Wno-unused-parameter', '-Wno-unused-function', '-Wno-type-limits', '-Wno-missing-braces', '-Wno-attributes'])
    commonenv.Append(CFLAGS = ['-Wstrict-prototypes'])
commonenv.Append(CPPPATH = ['#/inc'])

# Core libraries
libenv = commonenv.Clone()

libenv.Append(CPPDEFINES = ['MBEDTLS_USER_CONFIG_FILE=\\"mbedtls_config.h\\"'])
if env['PLATFORM'] == 'posix':
    libenv.Append(CPPDEFINES = ['_GNU_SOURCE'])
libenv.Append(CPPPATH = ['#/ext/safestring/include', '#/ext', '#/ext/mbedtls/include'])
if extUV: libenv.Append(CPPPATH = ['#/ext/libuv/include'])

# Include the fuzzing hooks when the sanitizer is enabled
if env['PLATFORM'] == 'posix' and env['fsan'] == True:
    libenv.Append(CPPDEFINES = ['DPS_USE_FUZZ'])

libenv.Install('#/build/dist/inc/dps', libenv.Glob('#/inc/dps/*.h'))
libenv.Install('#/build/dist/inc/dps/private', libenv.Glob('#/inc/dps/private/*.h'))

srcs = ['src/bitvec.c',
        'src/cbor.c',
        'src/cose.c',
        'src/coap.c',
        'src/dps.c',
        'src/pub.c',
        'src/sub.c',
        'src/ack.c',
        'src/dbg.c',
        'src/err.c',
        'src/event.c',
        'src/history.c',
        'src/json.c',
        'src/keystore.c',
        'src/synchronous.c',
        'src/uuid.c',
        'src/linkmon.c',
        'src/network.c',
        'src/registration.c',
        'src/resolver.c',
        'src/topics.c',
        'src/uv_extra.c',
        'src/sha2.c',
        'src/gcm.c',
        'src/ec.c',
        'src/hkdf.c',
        'src/keywrap.c',
        'src/mbedtls.c',
        'src/queue.c']

if env['transport'] == 'udp':
    srcs.extend(['src/multicast/network.c',
                 'src/udp/network.c'])
elif env['transport'] == 'dtls':
    srcs.extend(['src/multicast/network.c',
                 'src/dtls/network.c'])
elif env['transport'] == 'tcp':
    srcs.extend(['src/multicast/network.c',
                 'src/tcp/network.c'])
elif env['transport'] == 'pipe':
    srcs.extend(['src/multicast/network.c',
                 'src/pipe/network.c'])
elif env['transport'] == 'fuzzer':
    srcs.extend(['src/fuzzer/network.c'])

Depends(srcs, ext_objs)

objs = libenv.Object(srcs)

lib = libenv.Library('lib/dps', [objs, ext_objs])
installed_lib = libenv.Install('#/build/dist/lib', lib)

shobjs = libenv.SharedObject(srcs) + ext_shobjs
if libenv['CC'] == 'cl':
    shlib = libenv.SharedLibrary('lib/dps_shared', shobjs + [env['DEF_FILE']], LIBS = env['DPS_LIBS'], SHLIBVERSION = version)
elif libenv['PLATFORM'] == 'win32':
    shlib = libenv.SharedLibrary('lib/dps_shared', shobjs, LIBS = env['DPS_LIBS'])
else:
    shlib = libenv.SharedLibrary('lib/dps_shared', shobjs, LIBS = env['DPS_LIBS'], SHLIBVERSION = version)
libenv.InstallVersionedLib('#/build/dist/lib', shlib, SHLIBVERSION = version)

ns3srcs = ['src/bitvec.c',
           'src/cbor.c',
           'src/gcm.c',
           'src/coap.c',
           'src/cose.c',
           'src/dps.c',
           'src/pub.c',
           'src/sha2.c',
           'src/sub.c',
           'src/ack.c',
           'src/err.c',
           'src/history.c',
           'src/uuid.c',
           'src/topics.c']

if env['PLATFORM'] == 'posix':
    ns3shobjs = libenv.SharedObject(ns3srcs)
    ns3shlib = libenv.SharedLibrary('lib/dps_ns3', ns3shobjs + ext_shobjs)
    libenv.Install('#/build/dist/lib', ns3shlib)

swig_docs = []
if env['python']:
    if env['PLATFORM'] == 'posix' or env['CC'] == 'cl':
        # Using SWIG to build the python wrapper
        pyenv = libenv.Clone()
        pyenv.VariantDir('swig/py', 'swig')
        pyenv.Append(LIBPATH = env['PY_LIBPATH'])
        pyenv.Append(CPPPATH = env['PY_CPPPATH'])
        pyenv.Append(LIBS = [lib, env['DPS_LIBS']])
        # Documentation is only available which Doxygen is installed
        try:
            if pyenv.Doxygen:
                pyenv.Append(SWIGFLAGS = ['-DINCLUDE_DOC'])
        except AttributeError:
            pass
        # Python has platform specific naming conventions
        pyenv['SHLIBPREFIX'] = '_'
        if pyenv['CC'] == 'cl':
            pyenv['SHLIBSUFFIX'] = '.pyd'
            pyenv.Append(CCFLAGS = ['/EHsc'])
            # Ignore warnings in generated code
            pyenv.Append(CCFLAGS = ['/wd4244', '/wd4703'])
        elif 'gcc' in pyenv['CC']:
            pyenv.Append(CCFLAGS = ['-Wno-ignored-qualifiers', '-Wno-cast-function-type'])
        elif 'clang' in pyenv['CC']:
            pyenv.Append(CCFLAGS = ['-Wno-deprecated-register', '-Wno-ignored-qualifiers'])

        pyenv.Append(SWIGFLAGS = ['-python', '-c++', '-Wextra', '-Werror', '-v', '-O'], SWIGPATH = ['#/inc', './swig/py'])
        pyenv.Append(CPPPATH = ['swig', 'swig/py'])
        # Build python module library
        pyobjs = pyenv.SharedObject(['swig/py/dps.i'])
        pylib = pyenv.SharedLibrary('./py/dps', shobjs + pyobjs)
        pyenv.Install('#/build/dist/py', pylib)
        pyenv.InstallAs('#/build/dist/py/dps.py', './swig/py/dps.py')
        # Build documentation
        swig_docs += ['swig/py/dps_doc.i']
    else:
        print('Python binding only supported on the posix platform or with the cl compiler')
        exit()

if env['nodejs']:
    if env['PLATFORM'] == 'posix':
        # Use SWIG to build the node.js wrapper
        nodeenv = libenv.Clone();
        nodeenv.VariantDir('swig/js', 'swig')
        nodeenv.Append(SWIGFLAGS = ['-javascript', '-node', '-c++', '-DV8_VERSION=0x04059937', '-Wextra', '-Werror', '-v', '-O'], SWIGPATH = ['#/inc', './swig/js'])
        # There may be a bug with the SWIG builder - add -O to CPPFLAGS to get it passed on to the compiler
        nodeenv.Append(CPPDEFINES = ['BUILDING_NODE_EXTENSION'])
        nodeenv.Append(CCFLAGS = ['-std=c++11', '-O', '-Wno-unused-result', '-Wno-ignored-qualifiers'])
        if 'gcc' in nodeenv['CC']:
            nodeenv.Append(CCFLAGS = ['-Wno-cast-function-type'])
        nodeenv.Append(CPPPATH = ['swig', 'swig/js'])
        if env['target'] == 'yocto':
            nodeenv.Append(CPPPATH = [os.getenv('SYSROOT') + '/usr/include/node'])
        else:
            nodeenv.Append(CPPPATH = ['/usr/include/node'])
        nodeenv.Append(LIBS = [lib, env['DPS_LIBS']])
        nodeobjs = nodeenv.SharedObject(['swig/js/dps.i'])
        nodedps = nodeenv.SharedLibrary('lib/nodedps', shobjs + nodeobjs)
        nodeenv.InstallAs('#/build/dist/js/dps.node', nodedps)
        # Build documentation
        swig_docs += ['swig/js/dps.jsdoc']
    else:
        print('Node.js binding only supported on the posix platform')
        exit()

goimport1_re = re.compile(r'^import\s+"([^"]+)"', re.M)
goimportn_re = re.compile(r'^import\s+\(([^)]+)\)', re.M)
def gosrc_scanner(node, env, path):
    imports = []
    contents = node.get_text_contents()
    for i in goimport1_re.findall(contents) + goimportn_re.findall(contents):
        for j in i.split():
            pkg = j.strip('\"')
            imports += env.Glob('{}/src/{}/*.go'.format(env['GOPATH'], pkg))
            imports += env.Glob('{}/pkg/{}_{}/{}{}'.format(env['GOPATH'], env['ENV']['GOOS'], env['ENV']['GOARCH'], pkg, env['LIBSUFFIX']))
    # Special case for dps.go: any src file importing it also depends on the DPS libraries
    if any('dps.go' in str(i) for i in imports):
        imports += lib
    return imports
go_scanner = Scanner(function = gosrc_scanner,
                     skeys = ['.go'])

def gopkg_generator(target, source, env, for_signature):
    t = str(target[0]).replace(os.path.sep, '/')
    t = os.path.splitext(re.sub(r'.*/go/pkg/[^/]+/', r'', t))[0]
    return 'go install -a {}'.format(t)
def gopkg_emitter(target, source, env):
    src = 'dps/{}.go'.format(source[0])
    pkg = '{}{}'.format(os.path.dirname(src), env['LIBSUFFIX'])
    return 'go/pkg/{}_{}/'.format(env['ENV']['GOOS'], env['ENV']['GOARCH']) + pkg, 'go/src/' + src
gopkg = Builder(generator = gopkg_generator,
                emitter = gopkg_emitter,
                source_scanner = go_scanner)

def gobin_generator(target, source, env, for_signature):
    t = str(source[0]).replace(os.path.sep, '/')
    t = os.path.dirname(re.sub(r'.*/go/src/', r'', t))
    return 'go install -a {}'.format(t)
def gobin_emitter(target, source, env):
    src = 'dps/{}.go'.format(source[0])
    bin = os.path.basename(str(source[0]))
    return 'go/bin/' + bin, 'go/src/' + src
gobin = Builder(generator = gobin_generator,
                emitter = gobin_emitter,
                source_scanner = go_scanner)

if env['go']:
    if 'gcc' in env['CC']:
        goenv = libenv.Clone()
        goenv.AppendENVPath('GOOS', os.popen('go env GOOS').read().strip())
        goenv.AppendENVPath('GOARCH', os.popen('go env GOARCH').read().strip())
        # Append our GOPATH to the environment seen by the go tools and also remember it for use by the
        # scanner to locate imports.
        goenv.AppendENVPath('GOPATH', goenv.Dir('go').abspath)
        goenv.Append(GOPATH = goenv.Dir('go').abspath)
        goenv.Append(LIBS = env['DPS_LIBS'])
        cgo_cflags = ' '.join(['-I' + goenv.GetBuildPath(p) for p in goenv['CPPPATH']])
        cgo_ldflags = ' '.join(l.abspath for l in lib) + ' ' + ' '.join(['-l' + l for l in goenv['LIBS']])
        goenv.AppendENVPath('CGO_CFLAGS', cgo_cflags)
        goenv.AppendENVPath('CGO_LDFLAGS', cgo_ldflags)

        goenv.Append(BUILDERS = {'GoPkg' : gopkg})
        goenv.Append(BUILDERS = {'GoBin' : gobin})

        goenv.VariantDir('go/src/dps', 'go')
        for p in ['dps',
                  'examples/keys/keys']:
            goenv.GoPkg(p)
        for b in ['examples/simple_sub_ks/simple_sub_ks',
                  'examples/simple_sub/simple_sub',
                  'examples/simple_pub_ks/simple_pub_ks',
                  'examples/simple_pub/simple_pub']:
            goenv.GoBin(b)
        for b in ['test/perf_publisher/perf_publisher',
                  'test/perf_subscriber/perf_subscriber']:
            goenv.GoBin(b)
        goenv.Install('#/build/dist', 'go')
    else:
        print('Go binding only supported with the gcc compiler')
        exit()

# Unit tests
testenv = commonenv.Clone()
testenv.Append(CPPPATH = ['#/ext/safestring/include', 'src'])
testenv.Append(LIBS = [lib, env['DPS_LIBS']])
if extUV: testenv.Append(CPPPATH = ['#/ext/libuv/include'])

testsrcs = ['test/cbortest.c',
            'test/cosetest.c',
            'test/countvec.c',
            'test/hist_unit.c',
            'test/jsontest.c',
            'test/keystoretest.c',
            'test/make_mesh.c',
            'test/mesh_stress.c',
            'test/packtest.c',
            'test/pubsub.c',
            'test/rle_compression.c',
            'test/topic_match.c',
            'test/version.c']

Depends(testsrcs, ext_objs)

testobjs = testenv.Object(['test/keys.c',
                           'test/test.c'])

testprogs = []
for test in testsrcs:
    testprogs.append(testenv.Program([test, testobjs]))

testsrcs = ['test/link.c',
            'test/node.c',
            'test/publish.c']

for test in testsrcs:
    testprogs.append(testenv.Program([test, testobjs]))

testenv.Install('#/build/test/bin', testprogs)

psrcs = ['test/perf/publisher.c',
         'test/perf/subscriber.c']

Depends(psrcs, ext_objs)

pprogs = []
for test in psrcs:
    pprogs.append(testenv.Program([test, testobjs]))

testenv.Install('#/build/test/perf/bin', pprogs)

# Fuzz tests
if env['PLATFORM'] == 'posix' and env['fsan'] == True:
    fenv = commonenv.Clone()
    fenv.VariantDir('test/fuzzer', 'test')
    fenv.Append(CPPPATH = ['#/ext/safestring/include'])
    if extUV: fenv.Append(CPPPATH = ['#/ext/libuv/include'])
    fenv.Append(LINKFLAGS = ['-fsanitize=fuzzer'])
    fenv.Append(LIBS = [lib, env['DPS_LIBS']])

    fsrcs = ['test/fuzzer/cbor_fuzzer.c']
    if env['transport'] == 'dtls':
        fsrcs.extend(['test/fuzzer/dtls_fuzzer.c'])
    elif env['transport'] == 'fuzzer':
        fsrcs.extend(['test/fuzzer/net_receive_fuzzer.c',
                      'test/fuzzer/multicast_receive_fuzzer.c'])

    Depends(fsrcs, ext_objs)

    fprogs = []
    for f in fsrcs:
        fprogs.append(fenv.Program([f, 'test/fuzzer/keys.c']))

    fenv.Install('#/build/test/bin', fprogs)

# Examples
exampleenv = commonenv.Clone()
exampleenv.Append(LIBS = [lib, env['DPS_LIBS']])

examplesrcs = ['examples/pub_many.c',
               'examples/publisher.c',
               'examples/reg_pubs.c',
               'examples/reg_subs.c',
               'examples/subscriber.c',
               'examples/registry.c']

Depends(examplesrcs, ext_objs)

exampleprogs = []
for example in examplesrcs:
    exampleprogs.append(exampleenv.Program([example, 'examples/keys.c', 'examples/common.c']))

exampleenv.Install('#/build/dist/bin', exampleprogs)

# Tutorial examples
tutorialenv = commonenv.Clone()
tutorialenv.Append(LIBS = [lib, env['DPS_LIBS']])

tutorialsrcs = ['doc/tutorial/tutorial.c']

Depends(tutorialsrcs, ext_objs)

tutorialprogs = []
for tutorial in tutorialsrcs:
    tutorialprogs.append(tutorialenv.Program(tutorial))

tutorialenv.Install('#/build/dist/bin', tutorialprogs)

# Documentation
try:
    docs = libenv.Doxygen('doc/Doxyfile')
    libenv.Doxygen('doc/Doxyfile_dev')
    libenv.SwigDox(swig_docs, docs)
    if env['nodejs'] and env['PLATFORM'] == 'posix':
        libenv.InstallAs('#/build/dist/js/dps.jsdoc', 'swig/js/dps.jsdoc')
except:
    # Doxygen may not be installed
    pass

# Return the static DPS library
result = [lib]
Return('result')
