cmake_minimum_required(VERSION 3.8.2)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(dps_app)

include(ExternalProject)
find_package(Git REQUIRED)

set(ext_dir ${CMAKE_CURRENT_SOURCE_DIR}/../ext)
set(mbedtls_dir ${ext_dir}/mbedtls)

if(NOT EXISTS ${mbedtls_dir})
    execute_process(COMMAND ${GIT_EXECUTABLE} clone https://github.com/ARMmbed/mbedtls.git ${mbedtls_dir})
    execute_process(COMMAND ${GIT_EXECUTABLE} -C ${mdbedtls_dir} chekout tags/mbedtls-2.8.0)
endif()

add_compile_definitions(MBEDTLS_USER_CONFIG_FILE="${ext_dir}/mbedtls_config_zephyr.h")

include_directories("../include")
include_directories("${mbedtls_dir}/include")

add_compile_definitions(DPS_DEBUG=1)
add_compile_definitions(DPS_TARGET=DPS_TARGET_ZEPHYR)

set(mbedtls_sources
    ${mbedtls_dir}/library/aes.c
    ${mbedtls_dir}/library/aesni.c
    ${mbedtls_dir}/library/asn1write.c
    ${mbedtls_dir}/library/asn1parse.c
    ${mbedtls_dir}/library/base64.c
    ${mbedtls_dir}/library/bignum.c
    ${mbedtls_dir}/library/cipher.c
    ${mbedtls_dir}/library/cipher_wrap.c
    ${mbedtls_dir}/library/ctr_drbg.c
    ${mbedtls_dir}/library/debug.c
    ${mbedtls_dir}/library/ecdh.c
    ${mbedtls_dir}/library/ecdsa.c
    ${mbedtls_dir}/library/ecp.c
    ${mbedtls_dir}/library/ecp_curves.c
    ${mbedtls_dir}/library/entropy.c
    ${mbedtls_dir}/library/entropy_poll.c
    ${mbedtls_dir}/library/error.c
    ${mbedtls_dir}/library/gcm.c
    ${mbedtls_dir}/library/hmac_drbg.c
    ${mbedtls_dir}/library/md.c
    ${mbedtls_dir}/library/md_wrap.c
    ${mbedtls_dir}/library/md5.c
    ${mbedtls_dir}/library/oid.c
    ${mbedtls_dir}/library/pem.c
    ${mbedtls_dir}/library/pk.c
    ${mbedtls_dir}/library/pk_wrap.c
    ${mbedtls_dir}/library/pkparse.c
    ${mbedtls_dir}/library/platform.c
    ${mbedtls_dir}/library/sha256.c
    ${mbedtls_dir}/library/sha512.c
    ${mbedtls_dir}/library/timing.c
    ${mbedtls_dir}/library/x509.c
    ${mbedtls_dir}/library/x509_crt.c
    ${mbedtls_dir}/library/ssl_cache.c
    ${mbedtls_dir}/library/ssl_ciphersuites.c
    ${mbedtls_dir}/library/ssl_cli.c
    ${mbedtls_dir}/library/ssl_cookie.c
    ${mbedtls_dir}/library/ssl_srv.c
    ${mbedtls_dir}/library/ssl_tls.c
)

FILE(GLOB dps_sources "../src/*.c")

target_sources(app PRIVATE "../src/zephyr/network.c")
target_sources(app PRIVATE "../src/zephyr/dbg.c")
target_sources(app PRIVATE "../src/zephyr/entropy.c")
target_sources(app PRIVATE "../src/zephyr/malloc.c")
target_sources(app PRIVATE ${dps_sources})
target_sources(app PRIVATE ${mbedtls_sources})

# The application to build
include_directories("../test")
target_sources(app PRIVATE "../test/keys.c")
target_sources(app PRIVATE "../test/pub_unit_test.c")
