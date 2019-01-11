set ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
set GNUARMEMB_TOOLCHAIN_PATH=c:\gnu_arm_tools
cmake -Bbuild -DBOARD=stm32f746g_disco -GNinja .
