
find_package(NabtoCommon COMPONENTS nn)
add_library(np_platform STATIC "${ne_platform_src}")
target_link_libraries(np_platform PUBLIC NabtoCommon::nn)
