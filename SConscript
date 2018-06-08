import os
import string
Import(['env', 'ext_libs', 'version'])

platform = env['PLATFORM']

env['UV_LIBS'] = [ext_libs] + env['UV_LIBS']

# Additional warning for the lib object files

# Core libraries
libenv = env.Clone()

libenv.Append(CPPDEFINES = ['MBEDTLS_USER_CONFIG_FILE=\\"mbedtls_config.h\\"'])
libenv.Append(CPPPATH = ['#/ext/safestring/include', '#/ext', '#/ext/mbedtls/include'])

# Additional warnings for the core object files
if platform == 'win32':
    # We are getting our secure memory and string functions for
    # SafeStringLib so need to disable the Windows supplied versions
    libenv.Append(CPPDEFINES = ['__STDC_WANT_SECURE_LIB__=0'])
    libenv.Append(LIBS = env['UV_LIBS'])
elif platform == 'posix':
    libenv.Append(CCFLAGS = ['-Wall', '-Wno-format-extra-args'])

# Include the fuzzing hooks when the sanitizer is enabled
if platform == 'posix' and env['fsan'] == True:
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
        'src/mbedtls.c']

if env['transport'] == 'udp':
    srcs.extend(['src/multicast/network.c',
                 'src/udp/network.c'])
elif env['transport'] == 'dtls':
    srcs.extend(['src/multicast/network.c',
                 'src/dtls/network.c'])
elif env['transport'] == 'tcp':
    srcs.extend(['src/multicast/network.c',
                 'src/tcp/network.c'])
elif env['transport'] == 'fuzzer':
    srcs.extend(['src/fuzzer/network.c'])

Depends(srcs, ext_libs)

objs = libenv.Object(srcs)

lib = libenv.Library('lib/dps', objs)
libenv.Install('#/build/dist/lib', lib)

shobjs = libenv.SharedObject(srcs)
if platform == 'win32':
    shlib = libenv.SharedLibrary('lib/dps_shared', shobjs + ['dps_shared.def'], LIBS = env['UV_LIBS'], SHLIBVERSION = version)
else:
    shlib = libenv.SharedLibrary('lib/dps_shared', shobjs, LIBS = env['UV_LIBS'], SHLIBVERSION = version)
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

if platform == 'posix':
    ns3shobjs = libenv.SharedObject(ns3srcs)
    ns3shlib = libenv.SharedLibrary('lib/dps_ns3', ns3shobjs, LIBS = ext_libs)
    libenv.Install('#/build/dist/lib', ns3shlib)

swig_docs = []
if env['python']:
    # Using SWIG to build the python wrapper
    pyenv = libenv.Clone()
    pyenv.VariantDir('swig/py', 'swig')
    pyenv.Append(LIBPATH = env['PY_LIBPATH'])
    pyenv.Append(CPPPATH = env['PY_CPPPATH'])
    pyenv.Append(LIBS = [lib, env['UV_LIBS']])
    # Documentation is only available which Doxygen is installed
    try:
        if pyenv.Doxygen:
            pyenv.Append(SWIGFLAGS = ['-DINCLUDE_DOC'])
    except AttributeError:
        pass
    # Python has platform specific naming conventions
    pyenv['SHLIBPREFIX'] = '_'
    if platform == 'win32':
        pyenv['SHLIBSUFFIX'] = '.pyd'
        pyenv.Append(CCFLAGS = ['/EHsc'])
        # Ignore warnings in generated code
        pyenv.Append(CCFLAGS = ['/wd4244'])
    elif platform == 'posix':
        pyenv.Append(CCFLAGS = ['-Wno-deprecated-register'])

    pyenv.Append(SWIGFLAGS = ['-python', '-c++', '-Wextra', '-Werror', '-v', '-O'], SWIGPATH = ['#/inc', './swig/py'])
    pyenv.Append(CPPPATH = ['swig', 'swig/py'])
    # Build python module library
    pyobjs = pyenv.SharedObject(['swig/py/dps.i'])
    pylib = pyenv.SharedLibrary('./py/dps', shobjs + pyobjs)
    pyenv.Install('#/build/dist/py', pylib)
    pyenv.InstallAs('#/build/dist/py/dps.py', './swig/py/dps.py')
    # Build documentation
    swig_docs += ['swig/py/dps_doc.i']

if env['nodejs'] and platform == 'posix':
    # Use SWIG to build the node.js wrapper
    nodeenv = libenv.Clone();
    nodeenv.VariantDir('swig/js', 'swig')
    nodeenv.Append(SWIGFLAGS = ['-javascript', '-node', '-c++', '-DV8_VERSION=0x04059937', '-Wextra', '-Werror', '-v', '-O'], SWIGPATH = ['#/inc', './swig/js'])
    # There may be a bug with the SWIG builder - add -O to CPPFLAGS to get it passed on to the compiler
    nodeenv.Append(CPPFLAGS = ['-DBUILDING_NODE_EXTENSION', '-std=c++11', '-O', '-Wno-unused-result'])
    nodeenv.Append(CPPPATH = ['swig', 'swig/js'])
    if env['target'] == 'yocto':
        nodeenv.Append(CPPPATH = [os.getenv('SYSROOT') + '/usr/include/node'])
    else:
        nodeenv.Append(CPPPATH = ['/usr/include/node'])
    nodeenv.Append(LIBS = [lib, env['UV_LIBS']])
    nodeobjs = nodeenv.SharedObject(['swig/js/dps.i'])
    nodedps = nodeenv.SharedLibrary('lib/nodedps', shobjs + nodeobjs)
    nodeenv.InstallAs('#/build/dist/js/dps.node', nodedps)
    # Build documentation
    swig_docs += ['swig/js/dps.jsdoc']

# Unit tests
testenv = env.Clone()
if testenv['PLATFORM'] == 'win32':
    testenv.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS', '__STDC_WANT_SECURE_LIB__=0'])
testenv.Append(CPPPATH = ['#/ext/safestring/include', 'src'])
testenv.Append(LIBS = [lib, env['UV_LIBS']])

testsrcs = ['test/hist_unit.c',
            'test/make_mesh.c',
            'test/mesh_stress.c',
            'test/countvec.c',
            'test/rle_compression.c',
            'test/topic_match.c',
            'test/pubsub.c',
            'test/packtest.c',
            'test/cbortest.c',
            'test/cosetest.c',
            'test/version.c',
            'test/keystoretest.c']

Depends(testsrcs, ext_libs)

testprogs = []
for test in testsrcs:
    testprogs.append(testenv.Program(test))

testsrcs = ['test/link.c',
            'test/node.c',
            'test/publish.c']

for test in testsrcs:
    testprogs.append(testenv.Program([test, 'test/keys.c']))

testenv.Install('#/build/test/bin', testprogs)

# Fuzz tests
if platform == 'posix' and env['fsan'] == True:
    fenv = env.Clone()
    fenv.VariantDir('test/fuzzer', 'test')
    fenv.Append(CPPPATH = ['#/ext/safestring/include'])
    fenv.Append(LINKFLAGS = ['-fsanitize=fuzzer'])
    fenv.Append(LIBS = [lib, env['UV_LIBS']])

    fsrcs = ['test/fuzzer/cbor_fuzzer.c']
    if env['transport'] == 'dtls':
        fsrcs.extend(['test/fuzzer/dtls_fuzzer.c'])
    elif env['transport'] == 'fuzzer':
        fsrcs.extend(['test/fuzzer/net_receive_fuzzer.c',
                      'test/fuzzer/multicast_receive_fuzzer.c'])

    Depends(fsrcs, ext_libs)

    fprogs = []
    for f in fsrcs:
        fprogs.append(fenv.Program([f, 'test/fuzzer/keys.c']))

    fenv.Install('#/build/test/bin', fprogs)

# Examples
exampleenv = env.Clone()
if exampleenv['PLATFORM'] == 'win32':
    exampleenv.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS'])
exampleenv.Append(LIBS = [lib, env['UV_LIBS']])

examplesrcs = ['examples/pub_many.c',
               'examples/publisher.c',
               'examples/reg_pubs.c',
               'examples/reg_subs.c',
               'examples/subscriber.c',
               'examples/registry.c']

Depends(examplesrcs, ext_libs)

exampleprogs = []
for example in examplesrcs:
    exampleprogs.append(exampleenv.Program([example, 'examples/keys.c']))

exampleenv.Install('#/build/dist/bin', exampleprogs)

# Tutorial examples
tutorialenv = env.Clone()
if tutorialenv['PLATFORM'] == 'win32':
    tutorialenv.Append(CPPDEFINES = ['_CRT_SECURE_NO_WARNINGS'])
tutorialenv.Append(LIBS = [lib, env['UV_LIBS']])

tutorialsrcs = ['doc/tutorial/tutorial.c']

Depends(tutorialsrcs, ext_libs)

tutorialprogs = []
for tutorial in tutorialsrcs:
    tutorialprogs.append(tutorialenv.Program(tutorial))

tutorialenv.Install('#/build/dist/bin', tutorialprogs)

# Documentation
try:
    docs = libenv.Doxygen('doc/Doxyfile')
    libenv.Doxygen('doc/Doxyfile_dev')
    libenv.SwigDox(swig_docs, docs)
    if env['nodejs'] and platform == 'posix':
        libenv.InstallAs('#/build/dist/js/dps.jsdoc', 'swig/js/dps.jsdoc')
except:
    # Doxygen may not be installed
    pass
