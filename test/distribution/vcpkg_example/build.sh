DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

SOURCE_DIR=${DIR}/../../..
BUILD_DIR=${SOURCE_DIR}/build/vcpkg_example
INSTALL_DIR=${BUILD_DIR}/install

mkdir -p ${BUILD_DIR}

set -v
set -e

cd ${BUILD_DIR}

#Explanation:
# * The CMAKE_MODULE_PATH is needed since vcpkg still provides MbedTLS 2 and
#   tinycbor which does not come with find_package scripts.
# * The CMAKE_TOOLCHAIN_FILE is set such that the cmake build system will use
#   vcpkg
# * The VCPKG_OVERLAY_PORTS is set such that the NabtoEmbeddedSDK package can be
#   found since it is not present in the vcpkg package repository.

cmake -DCMAKE_MODULE_PATH=${SOURCE_DIR}/cmake/vcpkg  -DCMAKE_TOOLCHAIN_FILE=${SOURCE_DIR}/3rdparty/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_OVERLAY_PORTS=${DIR}/ports ${DIR}
make -j 16

./vcpkg_example
