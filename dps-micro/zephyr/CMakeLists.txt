cmake_minimum_required(VERSION 3.8.2)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(dps_app)

include_directories("../include")
include_directories("../ext/mbedtls/include")

add_compile_definitions(DPS_DEBUG=1)
add_compile_definitions(DPS_TARGET=DPS_TARGET_ZEPHYR)
add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="../ext/mbedtls_config.h")

FILE(GLOB ext_sources "../ext/mbedtls/library/*.c")
FILE(GLOB dps_sources "../src/*.c")

target_sources(app PRIVATE "../src/zephyr/network.c")
target_sources(app PRIVATE "../src/zephyr/dbg.c")
target_sources(app PRIVATE "../src/zephyr/entropy.c")
target_sources(app PRIVATE ${dps_sources})
target_sources(app PRIVATE ${ext_sources})

# The application to build
include_directories("../test")
target_sources(app PRIVATE "../test/keys.c")
target_sources(app PRIVATE "../test/pub_unit_test.c")
