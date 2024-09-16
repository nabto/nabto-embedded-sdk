DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

SOURCE_DIR=${DIR}/../../..
BUILD_DIR=${SOURCE_DIR}/build/vcpkg_example
INSTALL_DIR=${BUILD_DIR}/install

mkdir -p ${BUILD_DIR}

set -v
set -e

cd ${BUILD_DIR}
cmake -DCMAKE_MODULE_PATH=${SOURCE_DIR}/cmake/vcpkg  -DCMAKE_TOOLCHAIN_FILE=${SOURCE_DIR}/3rdparty/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_OVERLAY_PORTS=${DIR}/ports ${DIR}
make -j 16

./vcpkg_example
