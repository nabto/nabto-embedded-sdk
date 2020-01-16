set(src
  iam_to_json.cpp
  )

add_library(iam_cpp "${src}")
target_link_libraries(iam_cpp 3rdparty_json)
