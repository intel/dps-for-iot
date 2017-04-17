SUMMARY = "distributed pub/sub"
DESCRIPTION = "distributed pub/sub examples and lib."

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE.md;md5=048191255019d4e1ee70aef53dbbec10"

S = "${WORKDIR}/git"
SRCREV_dps = "59a3c33d64f2b3fc16cc5c52b5f4a7bec47640a7"
SRCREV_tinycrypt = "e6cffb820b91578d9816fc0bcc8f72f32f6ee76b"
SRCREV_safestring = "db404a9bba3a58d06adfdab4021e7b91265ac0f0"
PV = "0.1+git${SRCPV}"
PR = "r0"

SRCREV_FORMAT = "dps"
SRC_URI = "git://github.com/01org/dps-for-iot.git;name=dps \
           git://github.com/01org/tinycrypt.git;protocol=https;name=tinycrypt;destsuffix=git/ext/tinycrypt \
           git://github.com/01org/safestringlib.git;protocol=https;name=safestring;destsuffix=git/ext/safestring \
           "
inherit scons

DEPENDS = "libuv nodejs python-scons-native python"

INSANE_SKIP_${PN} += " ldflags"
INSANE_SKIP_${PN}-dev += "ldflags"
INSANE_SKIP_${PN}-dbg += "ldflags"

ERROR_QA_remove = "ldflags"
WARN_QA_append = " ldflags"

EXTRA_OESCONS = " \
    sysroot=${STAGING_DIR_TARGET} \
"

do_compile_prepend() {
    export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
    export PKG_CONFIG="PKG_CONFIG_SYSROOT_DIR=\"${PKG_CONFIG_SYSROOT_DIR}\" pkg-config"
    export STAGING_PREFIX="${STAGING_DIR_HOST}/${prefix}"
    export LINKFLAGS="${LDFLAGS}"
    export SYSROOT="${STAGING_DIR_TARGET}"
}
scons_do_compile() {
    ${STAGING_BINDIR_NATIVE}/scons target=yocto ${PARALLEL_MAKE} ${EXTRA_OESCONS} || \
    die "scons build execution failed."
}

do_install() {
    install -d ${D}${libdir}/dps
    install -m 0755 ${WORKDIR}/git/build/dist/lib/libdps_shared.so ${D}${libdir}/dps/libdps_shared.so
    install -m 0755 ${WORKDIR}/git/build/dist/lib/libdps.a ${D}${libdir}/dps/libdps.a

    install -d ${D}/${libdir}/dps/bin
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/publisher ${D}/${libdir}/dps/bin/publisher
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/pub_many ${D}/${libdir}/dps/bin/pub_many
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/registry ${D}/${libdir}/dps/bin/registry
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/reg_pubs ${D}/${libdir}/dps/bin/reg_pubs
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/reg_subs ${D}/${libdir}/dps/bin/reg_subs
    install -c -m 0755 ${WORKDIR}/git/build/dist/bin/subscriber ${D}/${libdir}/dps/bin/subscriber
}

PACKAGES =+ "${PN}-tests"

RDEPENDS_${PN} += "libuv"
ALLOW_EMPTY_${PN}-staticdev = "1"

FILES_${PN} += "${libdir}/dps/libdps_shared.so"

FILES_${PN}-staticdev += "${libdir}/dps/libdps.a"

FILES_${PN}-tests += "${libdir}/dps/bin/publisher \
                    ${libdir}/dps/bin/pub_many \
                    ${libdir}/dps/bin/registry \
                    ${libdir}/dps/bin/reg_pubs \
                    ${libdir}/dps/bin/reg_subs \
                    ${libdir}/dps/bin/subscriber"
