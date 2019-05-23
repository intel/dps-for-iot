#!/bin/bash
set -e

# Fetch the latest rmw_dps and patch it to use the current dps-for-iot sources
export RMW_DPS_BUILD_DIR=${TRAVIS_BUILD_DIR}/../rmw_dps
git clone https://github.com/ros2/rmw_dps "${RMW_DPS_BUILD_DIR}"
sed -i 's|URL https://github.com/intel/dps-for-iot/archive/master.zip|URL /shared/dps-for-iot|g' "${RMW_DPS_BUILD_DIR}/dps_for_iot_cmake_module/CMakeLists.txt"
# Run rmw_dps CI script
bash ${RMW_DPS_BUILD_DIR}/travis_build.sh
