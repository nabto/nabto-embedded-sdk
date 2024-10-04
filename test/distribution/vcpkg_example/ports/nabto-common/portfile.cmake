set(REF "95c9cae4b085668c4221f43c0d874d981daba4b1")

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO nabto/nabto-common
    REF ${REF}
    SHA512 b4b45751df9eecce634f740d61a481625001e0669a250fb72499c760f3b0b46bb51121ca8041e2708f3a3b7e022a62b2b3137dac353e82ea6924fc9b6c2a7da8
    HEAD_REF "master"
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
     -DNABTO_COMMON_VERSION=0.0.0+${REF}
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_cmake_config_fixup(PACKAGE_NAME NabtoCommon CONFIG_PATH lib/cmake/NabtoCommon)

#vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSING.md")
