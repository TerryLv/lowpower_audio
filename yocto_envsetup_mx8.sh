export SDKTARGETSYSROOT=/home/terry/fsl-release-bsp-imx8/build-wayland/tmp/sysroots/imx8mqevk
export PATH=/home/terry/fsl-release-bsp-imx8/build-wayland/tmp/sysroots/x86_64-linux/usr/bin/aarch64-poky-linux:$PATH
export PKG_CONFIG_SYSROOT_DIR=$SDKTARGETSYSROOT
export PKG_CONFIG_PATH=${SDKTARGETSYSROOT}/usr/lib/pkgconfig
export OECORE_NATIVE_SYSROOT="$SDKTARGETSYSROOT"
export OECORE_TARGET_SYSROOT="$SDKTARGETSYSROOT"
#export CC="${COMPILE_PREFIX}}gcc  -march=armv7-a -mfloat-abi=hard -mfpu=neon -mtune=cortex-a7 --sysroot=$SDKTARGETSYSROOT"
#export CXX="${COMPILE_PREFIX}}g++  -march=armv7-a -mfloat-abi=hard -mfpu=neon -mtune=cortex-a7 --sysroot=$SDKTARGETSYSROOT"
#export CPP="${COMPILE_PREFIX}}gcc -E  -march=armv7-a -mfloat-abi=hard -mfpu=neon -mtune=cortex-a7 --sysroot=$SDKTARGETSYSROOT"
export COMPILE_PREFIX_NO_DASH=aarch64-poky-linux
export COMPILE_PREFIX=${COMPILE_PREFIX_NO_DASH}-
export CC="${COMPILE_PREFIX}gcc  --sysroot=$SDKTARGETSYSROOT"
export CXX="${COMPILE_PREFIX}g++ --sysroot=$SDKTARGETSYSROOT"
export CPP="${COMPILE_PREFIX}gcc -E --sysroot=$SDKTARGETSYSROOT"
export AS="${COMPILE_PREFIX}as "
export LD="${COMPILE_PREFIX}ld  --sysroot=$SDKTARGETSYSROOT"
export GDB=${COMPILE_PREFIX}gdb
export STRIP=${COMPILE_PREFIX}strip
export RANLIB=${COMPILE_PREFIX}ranlib
export OBJCOPY=${COMPILE_PREFIX}objcopy
export OBJDUMP=${COMPILE_PREFIX}objdump
export AR=${COMPILE_PREFIX}ar
export NM=${COMPILE_PREFIX}nm
export M4=m4
export TARGET_PREFIX=${COMPILE_PREFIX}
export CONFIGURE_FLAGS="--target=${COMPILE_PREFIX_NO_DASH} --host=${COMPILE_PREFIX_NO_DASH} --build=x86_64-linux --with-libtool-sysroot=$SDKTARGETSYSROOT"
#export CFLAGS=" -O2 -pipe -g -feliminate-unused-debug-types"
#export CXXFLAGS=" -O2 -pipe -g -feliminate-unused-debug-types"
#export LDFLAGS="-Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed"
#export CPPFLAGS=""
export KCFLAGS="--sysroot=$SDKTARGETSYSROOT"
export OECORE_DISTRO_VERSION="4.1.15-1.1.0"
export OECORE_SDK_VERSION="4.1.15-1.1.0"
export ARCH=arm
export CROSS_COMPILE=${COMPILE_PREFIX}

# Append environment subscripts
if [ -d "$OECORE_TARGET_SYSROOT/environment-setup.d" ]; then
    for envfile in $OECORE_TARGET_SYSROOT/environment-setup.d/*.sh; do
	    source $envfile
    done
fi
if [ -d "$OECORE_NATIVE_SYSROOT/environment-setup.d" ]; then
    for envfile in $OECORE_NATIVE_SYSROOT/environment-setup.d/*.sh; do
	    source $envfile
    done
fi
