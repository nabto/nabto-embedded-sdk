find_program(GIT "git")
if (NOT GIT)
  message(FATAL_ERROR "git executable not found")
endif()

execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND git rev-parse --is-inside-work-tree
  RESULT_VARIABLE IS_GIT_REPOSITORY)

if (NOT IS_GIT_REPOSITORY EQUAL 0)
  if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c)

    message(FATAL_ERROR "No file ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c exists and it cannot be auto generated as it is either not inside a git repository or the git command is not available.")
  endif()
else()
  # A git repo, generate nc_version.c

  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git diff --quiet --exit-code
    RESULT_VARIABLE GIT_DIRTY)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git describe --exact-match --tags
    OUTPUT_VARIABLE GIT_TAG ERROR_QUIET)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git rev-parse --abbrev-ref HEAD
    OUTPUT_VARIABLE GIT_BRANCH)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git rev-list --count HEAD
    OUTPUT_VARIABLE GIT_COUNT ERROR_QUIET)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git rev-parse --short HEAD
    OUTPUT_VARIABLE GIT_HASH ERROR_QUIET)

  if (GIT_DIRTY EQUAL 0)
    set(GIT_DIRTY "")
  else()
    set(GIT_DIRTY ".dirty")
  endif()


  string(STRIP "${GIT_DIRTY}" GIT_DIRTY)
  string(STRIP "${GIT_TAG}" GIT_TAG)
  string(STRIP "${GIT_BRANCH}" GIT_BRANCH)
  string(STRIP "${GIT_COUNT}" GIT_COUNT)
  string(STRIP "${GIT_BRANCH_COUNT}" GIT_BRANCH_COUNT)
  string(STRIP "${GIT_HASH}" GIT_HASH)

  message("version.cmake variables: GIT_DIRTY ${GIT_DIRTY}, GIT_TAG ${GIT_TAG}, GIT_BRANCH ${GIT_BRANCH}, GIT_COUNT ${GIT_COUNT}, GIT_BRANCH_COUNT ${GIT_BRANCH_COUNT}, GIT_HASH: ${GIT_HASH}")

  set(VERSION_NUMBER "5.2.0")

  if (GIT_TAG)
    # string v4.5.6 -> 4.5.6
    string(SUBSTRING ${GIT_TAG} 1 -1 VERSION)
  elseif (GIT_BRANCH MATCHES "^[0-9].*$")
    # This is a release branch e.g 5.1 or 5.1.1
    set(VERSION "${VERSION_NUMBER}-rc.${GIT_COUNT}+${GIT_HASH}${GIT_DIRTY}")
  else()
    # A feature branch
    set(VERSION "${VERSION_NUMBER}-${GIT_BRANCH}.${GIT_COUNT}+${GIT_HASH}${GIT_DIRTY}")
  endif()

  message("Generated the version: ${VERSION} based on the git repository information")

  set(VERSION "#include \"nc_version.h\"\n
static const char* nc_version_str = \"${VERSION}\"\n;
const char* nc_version() { return nc_version_str; }\n")

  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c VERSION_)
  else()
    set(VERSION_ "")
  endif()

  if (NOT "${VERSION}" STREQUAL "${VERSION_}")
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c "${VERSION}")
  endif()
endif()
