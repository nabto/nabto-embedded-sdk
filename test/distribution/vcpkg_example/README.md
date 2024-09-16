# vcpkg example

This example shows how the nabto embedded sdk can be used with the vcpkg package
management system. This is just an example, consult the vcpkg documentation for
further information.

usage:

cd into this directory.
```
mkdir build
cd build
cmake -DCMAKE_MODULE_PATH=`pwd`/../../../../cmake/vcpkg  -DCMAKE_TOOLCHAIN_FILE=`pwd`/../../../../3rdparty/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_OVERLAY_PORTS=`pwd`/../ports ..
make
./vcpkg_example
```

Explanation:
 * The CMAKE_MODULE_PATH is needed since vcpkg still provides MbedTLS 2 and
   tinycbor which does not come with find_package scripts.
 * The CMAKE_TOOLCHAIN_FILE is set such that the cmake build system will use
   vcpkg
 * The VCPKG_OVERLAY_PORTS is set such that the NabtoEmbeddedSDK package can be
   found since it is not present in the vcpkg package repository.
