set(src
  fingerprint_iam.cpp
  )

add_library(fingerprint_iam "${src}")
target_link_libraries(fingerprint_iam iam_cpp 3rdparty_tinycbor)
