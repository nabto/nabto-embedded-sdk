#!/bin/bash
#
# Build one or more Linux targets via CMake presets. Per-target config
# (generator, build type, triplet, chainload toolchain, install location) lives
# in CMakePresets.json; this script is just a thin orchestrator.
#
# All targets use Bootlin glibc cross toolchains instead of the host distro's
# toolchains. The bootlin toolchains pin glibc to 2.34 (stable-2021.11-1) so the
# resulting binaries run on older systems regardless of the build host. They are
# downloaded from our S3 asset bucket, extracted and relocated on demand, then
# wired into the build through a vcpkg overlay triplet that chainloads
# build-scripts/toolchains/bootlin.cmake (so both the vcpkg dependencies and the
# project itself are built with the bootlin compiler). bootlin.cmake reads the
# BOOTLIN_* environment variables this script exports — env (not -D cache)
# variables are used on purpose so they survive vcpkg's fresh sub-processes.
#
set -e

SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SDK_DIR="$( cd -P "$SCRIPT_DIR/.." && pwd )"

BUILD_ROOT="${SDK_DIR}/build"
TOOLCHAIN_CACHE="$BUILD_ROOT/toolchains"

BASE_URL="https://nabto-build-assets.s3.eu-west-1.amazonaws.com/toolchains"

ALL_TARGETS=(
    linux_x86_64
    linux_arm64
    linux_armv6
)

usage() {
    cat <<EOF
Usage: $0 <target> | all

Targets:
  all             Build every target below in sequence
$(printf '  %s\n' "${ALL_TARGETS[@]}")

Each target installs into build/<target>/install.
EOF
    exit "${1:-1}"
}

# Map a target to its bootlin tarball and CMAKE_SYSTEM_PROCESSOR. Sets the
# globals TARBALL and SYSPROC. The vcpkg triplet lives in the preset, so it is
# not set here.
target_config() {
    case "$1" in
        linux_x86_64)
            TARBALL="x86-64-core-i7--glibc--stable-2021.11-1.tar.bz2"
            SYSPROC="x86_64" ;;
        linux_arm64)
            TARBALL="aarch64--glibc--stable-2021.11-1.tar.bz2"
            SYSPROC="aarch64" ;;
        linux_armv6)
            TARBALL="armv6-eabihf--glibc--stable-2021.11-1.tar.bz2"
            SYSPROC="arm" ;;
        *)
            echo "Unknown target '$1'" >&2
            usage ;;
    esac
}

# Download, extract and relocate the bootlin toolchain for $TARBALL. Sets the
# globals TOOLCHAIN_ROOT, TOOLCHAIN_PREFIX and SYSROOT.
prepare_toolchain() {
    local tarball=$1
    local name="${tarball%.tar.bz2}"
    local root="$TOOLCHAIN_CACHE/$name"

    mkdir -p "$TOOLCHAIN_CACHE"

    if [ ! -f "$TOOLCHAIN_CACHE/$tarball" ]; then
        echo "==> Downloading $tarball"
        curl -fSL -o "$TOOLCHAIN_CACHE/$tarball" "$BASE_URL/$tarball"
    fi

    if [ ! -d "$root" ]; then
        echo "==> Extracting $tarball"
        tar xjf "$TOOLCHAIN_CACHE/$tarball" -C "$TOOLCHAIN_CACHE"
    fi

    # Bootlin toolchains embed absolute paths from the build machine; their
    # relocate-sdk.sh rewrites those to the current location. Run it once.
    if [ ! -f "$root/.relocated" ]; then
        echo "==> Relocating toolchain $name"
        ( cd "$root" && ./relocate-sdk.sh )
        touch "$root/.relocated"
    fi

    # Discover the compiler prefix (e.g. arm-buildroot-linux-gnueabihf-) from
    # the bin/<tuple>-gcc wrapper rather than hardcoding per-arch tuples.
    local gcc
    gcc=$(basename "$(find "$root/bin" -maxdepth 1 -name '*-gcc' | sort | head -n 1)")
    if [ -z "$gcc" ]; then
        echo "Could not find a *-gcc compiler under $root/bin" >&2
        exit 1
    fi
    TOOLCHAIN_ROOT="$root"
    TOOLCHAIN_PREFIX="${gcc%gcc}"
    SYSROOT="$("$root/bin/$gcc" -print-sysroot)"
}

# Configure, build and install one target using its CMake preset, after
# downloading/relocating its bootlin toolchain and exporting the BOOTLIN_*
# variables that build-scripts/toolchains/bootlin.cmake reads.
build_slice() {
    local preset=$1
    local build_dir="$BUILD_ROOT/$preset"
    local install_dir="$build_dir/install"

    target_config "$preset"

    echo "==> Building target=$preset"
    (
        prepare_toolchain "$TARBALL"
        export BOOTLIN_TOOLCHAIN_ROOT="$TOOLCHAIN_ROOT"
        export BOOTLIN_TOOLCHAIN_PREFIX="$TOOLCHAIN_PREFIX"
        export BOOTLIN_SYSROOT="$SYSROOT"
        export BOOTLIN_SYSTEM_PROCESSOR="$SYSPROC"

        cd "$SDK_DIR"
        cmake --preset "$preset"
        cmake --build   "$build_dir"
        cmake --install "$build_dir"
    )

    file "$install_dir/bin/tcp_tunnel_device"

    # Only the x86_64 binaries run on the (x86_64) build host. The ARM targets
    # would need qemu, so they are built but not tested.
    if [ "$preset" = "linux_x86_64" ]; then
        echo "==> Running tests for $preset"
        "$install_dir/bin/embedded_unit_test" -l test_suite --detect_memory_leaks=0
    fi
}

main() {
    [ $# -ge 1 ] || usage
    local target=$1

    case "$target" in
        -h|--help|help)
            usage 0 ;;
        all)
            for t in "${ALL_TARGETS[@]}"; do build_slice "$t"; done ;;
        *)
            build_slice "$target" ;;
    esac
}

main "$@"
