set(USE_LOCAL_GIT_CHECKOUT OFF)

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

if (NOT USE_LOCAL_GIT_CHECKOUT)

    vcpkg_from_github(
        OUT_SOURCE_PATH SOURCE_PATH
        REPO nabto/nabto-common
        REF "4d7329f62eec3e22d1870bcbdb960fb51d5c7ada"
        SHA512 7b0bbc92f46ff60b7174693bc03f30b591d6a78a12aeeaac8d677036270ca026695ab4a1fd14a9d0ea89b8c02981aed76a24767ac594c2874280f7867c4ea857
        HEAD_REF "master"
    )

    vcpkg_cmake_configure(
        SOURCE_PATH "${SOURCE_PATH}"
    )

else()

    string(TIMESTAMP CURRENT_TIME UTC)
        configure_file(
            ${CMAKE_CURRENT_LIST_DIR}/timestamp.txt.in
            ${CMAKE_CURRENT_LIST_DIR}/timestamp.txt
            @ONLY)

    vcpkg_cmake_configure(
        SOURCE_PATH "../../../../../nabto-common"
    )

endif()

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_cmake_config_fixup(PACKAGE_NAME NabtoCommon CONFIG_PATH lib/cmake/NabtoCommon)

#vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSING.md")
