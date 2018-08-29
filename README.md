# Distributed Publish & Subscribe for IoT

[![Build Status](https://travis-ci.org/intel/dps-for-iot.svg?branch=master)](https://travis-ci.org/intel/dps-for-iot)

Distributed Publish & Subscribe for IoT (DPS) is a new protocol that
implements the publish/subscribe (pub/sub) communication pattern.

Devices or applications running the protocol form a dynamic
multiply-connected mesh where each node functions as a message
router. The protocol is light-weight and amenable to implementation on
very small devices such as sensors that primarily publish data. The
architecture is well suited for applications that leverage edge
computing in combination with cloud-based analytics.

## [Building and Running](https://intel.github.io/dps-for-iot/building-and-running.html)

## [Documentation](https://intel.github.io/dps-for-iot)

In application subdirectory there is a simple SConscript that can be used as a template for
building your own statically linked DPS C application. Copy the application tree somewhere
and add your source and header files to the src and include directories.

To build:

scons -C <dps-root-dir> application=<your-application-dir> bindings=none

