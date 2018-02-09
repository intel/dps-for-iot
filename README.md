# Introduction to Distributed Publish Subscribe for IoT

***

### Note: This is a preview release of the software and is intended for evaluation and experimentation only.

***

## Install prerequisites


### Linux

- gcc or clang

- [SCons](http://scons.org/pages/download.html)

- libuv is used by node.js so packages are available for many
distributions but note that DPS requires libuv 1.7 or later so it may
be necessary to build libuv from source. [libuv source code on
GitHub.](https://github.com/libuv)

- [SWIG](http://www.swig.org/download.html)

---

### Windows
- [Visual Studio](https://www.visualstudio.com/downloads/)

  Note: In Visual Studio 2015, Visual C++ is not installed by default.
  When installing, be sure to choose <strong>Custom</strong>
  installation and then choose the C++ components you require. Or, if
  Visual Studio is already installed, choose <strong>File | New |
  Project | C++</strong> and you will be prompted to install the
  necessary components.

- [Latest Python 2.7 Release](https://www.python.org/downloads/windows/)

- [SCons](http://scons.org/pages/download.html)

  Note: The SCons installer will not detect the 64-bit installation of
  Python.  Instead, download the zip file and follow the installation
  instructions in SCons README.txt.

- [libuv](http://dist.libuv.org/dist/)

- [SWIG](http://www.swig.org/download.html)

---

### Yocto
Yocto Project through the OpenEmbedded build system provides an open
source development environment targeting the ARM, MIPS, PowerPC and
x86 architectures for a variety of platforms including x86-64 and
emulated ones.

- [Yocto git](https://git.yoctoproject.org/)

- [Yocto Project Quick Start](http://www.yoctoproject.org/docs/1.8/yocto-project-qs/yocto-project-qs.html)

- [Yocto libuv](https://layers.openembedded.org/layerindex/recipe/32082/)

---

## Documentation

The C API documentation is generated using Doxygen. There is currently
no support for generating API documentation for the Python or JS APIs.

Doxygen can be downloaded from here:
[Doxygen](http://www.stack.nl/~dimitri/doxygen/download.html)

Building the documentation requires the scons
[DoxygenBuilder](https://bitbucket.org/scons/scons/wiki/DoxygenBuilder)
tool.  This [page](https://bitbucket.org/scons/scons/wiki/ToolsIndex)
has instructions on how to install the builder.

---
## Build

### Linux and Windows
To build the DPS libraries, examples, bindings, and documentation run
'scons'.

	$ scons [variant=debug|release] [transport=udp|tcp|dtls] [bindings=all|none]

To build with a different compiler use the `CC` and `CXX` build
options.

	$ scons CC=clang CXX=clang++

To see the complete list of build options run `scons --help`.  The
default build configuration is `variant=release transport=udp
bindings=all`.

> A limitation of the current implementation is that the transport
> must be configured at compile time.

The scons script pulls down source code from two external projects
(mbedtls, and safestringlib) into the `./ext` directory. If necessary
these projects can be populated manually:

	git clone https://github.com/ARMmbed/mbedtls ext/mbedtls
	git clone https://github.com/01org/safestringlib.git ext/safestring

> The ext projects are populated the first time DPS is built. To
> update these projects you need to manually do a `git pull` or delete
> the project directory and rerun scons.

---

### Yocto
Clone the poky repository and configure the Yocto environment.  Refer
to [Yocto Project Quick
Start](http://www.yoctoproject.org/docs/1.8/yocto-project-qs/yocto-project-qs.html)
for more information.

Clone the libuv Yocto project and yocto/recipes-connectivity/dps to
the Yocto Project directory.  Modify the value of SRCREV_dps in
dps_git.bb to the last commit of dps.

The Yocto Project directory needs to be included in BBLAYERS of
conf/bblayers.conf.  Refer to [Yocto
Wiki](https://wiki.yoctoproject.org/wiki/How_do_I) for more
information.

From the root directory of the Yocto Project, initialize the Yocto
environment, provide a meaningful build directory name and build Yocto
DPS.

	$ source oe-init-build-env mybuilds
	$ bitbake dps

---

## Examples

There are C, Python, and JS (node.js) examples.

The C examples are found in `./examples`, the Python examples are in
`./py_scripts` and the JS examples are in `./js_scripts`.

The C examples are installed in `./build/dist/bin`. There are some
some test scripts in `./test_scripts` that run some more complex
scenarios using the example programs.  The test script **tree1**
builds a small mesh and shows how publications sent to any node in the
mesh get forwarded to the matching subscribers.  The script **reg1**
uses the *registry*, *reg_pubs*, and *reg_subs* examples programs to
build a dynamic mesh using the experimental discovery service.



