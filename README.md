# Introduction {#mainpage}

***

Note: NOT INTENDED FOR COMMERCIAL DEPLOYMENT.
=============================================

## This is a preview release of the software and is intended for evaluation and experimentation only.

***

## Install prerequisites


### Linux

- gcc

- [SCons](http://scons.org/pages/download.html)

- libuv is available in most distributions, DPS required libuv 2.7 or later

- [SCons](http://scons.org/pages/download.html)

- [SWIG](http://www.swig.org/download.html)

- [Doxygen](http://www.stack.nl/~dimitri/doxygen/download.html)

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

## Documentation

The C API documentation is generated using Doxygen. There is currently no support for generating API documentation for the Python or JS APIs.

Doxygen can be downloaded from here: [Doxygen](http://www.stack.nl/~dimitri/doxygen/download.html)

Building the documentation requires the scons [DoxygenBuilder](https://bitbucket.org/scons/scons/wiki/DoxygenBuilder) tool.  This [page](https://bitbucket.org/scons/scons/wiki/ToolsIndex) has instructions on how to install the builder.

---
## Build
To build the DPS libraries, examples, bidings, and documentation run 'scons'.

`$ scons [variant=debug|release] [transport=udp|tcp]`

The default build configuration is `variant=release transport=udp`.
> A limitation on the current implementation is that the transport must be configured at compile time.

The scons script pulls down source code from two external projects: tincrypt, and safestringlib.into the `./ext` directory. If necessary these projects can be populated manually:

`git clone https://github.com/01org/tinycrypt.git ext/tinycrypt`
`git clone https://github.com/01org/safestringlib.git ext/safestring`

>Note: the ext projects are populated the first time DPS is built. To update these projects you need to manually delete them and rerun scons.

## Examples

There are C, Python, and JS (node.js) examples.

The C examples are found in `./examples`, the Python examples are in `./py_scripts` and the JS examples are in `./js_scripts`.
There are currently six C samples:

- **publisher.c**

    This application shows how to initialize a DPS node, create a publication and send it.
    It supports IP multicast or publication to a specific host and port number over the configured
    transport (udp or tcp). Optionally the application will request acknowledgments
    from the receiving subscribers.
~~~~
    publisher a/b/c "hello world"
~~~~
    sends a single publication to the topic string **a/b/c** and exits.
- **subscriber.c**

    This application is the subscription counterpart to publisher.c, it creates a subscription and
    either listens for multicast publications or links another node to form a subscriber mesh.
~~~~
    subscriber a/b/c
    subscriber a/+/c
    subscriber a/#
~~~~
    listens for multicast subscriptions that match the specified topic string (in this case they all match **a/b/c**)
    and prints out information about the received publications.
- **registry.c**

    This applications uses DPS to implement an experimental discovery service. There are two
    companion applications, *reg_pubs* and *reg_subs* described below that make use of this service for
    find and join a mesh identified by a *tenant*  topic string.
- **reg_pubs.c**

    This application is similar to *publisher* but it uses the *registry* service to find other nodes to
    link with. The result is a multiply-connected (randomly connected) mesh.
- **reg_subs.c**

    This application is subscription counterpart to *reg_subs*, it uses the *registry* service to
    find other node and links into the mesh.
- **pub_many.c**

    This is application just sends a series of publications as fast as they are acknowledged.
    It can be used with the *subscriber* application.

The C examples are installed in `./build/dist/bin`. There are some some test scripts in
`./test_scripts` that run some more complex scenarios using the example programs.
The test script **tree1** builds a small mesh and shows how publications sent to
any node in the mesh get forwarded to the matching subscribers.
The script **reg1** uses the *registry*, *reg_pubs*, and *reg_subs* examples programs
to build a dynamic mesh using the experimental discovery service.


