project(cJSON VERSION 1.7.15)
  set(src
    cjson/cJSON.c
    )

  add_library(cjson ${src})
  add_library(cJSON::cjson ALIAS cjson)
  target_include_directories(cjson PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cjson>" "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

  target_sources(cjson PUBLIC
    FILE_SET public_headers
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
      FILES
      cjson/cJSON.h
  )

  include(GNUInstallDirs)
  set(config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
  set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

  set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
  set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
  set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
  set(namespace "${PROJECT_NAME}::")

  include(CMakePackageConfigHelpers)

  install(
      TARGETS cjson
      EXPORT "${TARGETS_EXPORT_NAME}"
      LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
      RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
      INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
      FILE_SET public_headers
  )

  write_basic_package_version_file(
      "${version_config}" COMPATIBILITY SameMajorVersion
  )

  configure_package_config_file(
      "cmake/Config.cmake.in"
      "${project_config}"
      INSTALL_DESTINATION "${config_install_dir}"
  )

  # Config
  #   * <prefix>/lib/cmake/Foo/FooConfig.cmake
  #   * <prefix>/lib/cmake/Foo/FooConfigVersion.cmake
  install(
      FILES "${project_config}" "${version_config}"
      DESTINATION "${config_install_dir}"
  )

  # Config
  #   * <prefix>/lib/cmake/Foo/FooTargets.cmake
  install(
      EXPORT "${TARGETS_EXPORT_NAME}"
      NAMESPACE "${namespace}"
      DESTINATION "${config_install_dir}"
  )
