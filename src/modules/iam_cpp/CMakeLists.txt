set(src
  iam_to_json.cpp
  iam.cpp
  attributes.cpp
  statement.cpp
  policy.cpp
  decision.cpp
  condition.cpp
  )

add_library(iam_cpp "${src}")
target_link_libraries(iam_cpp 3rdparty_json)
