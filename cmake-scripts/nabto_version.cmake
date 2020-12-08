# Calculate the version from the current git repository.

# This script is copied from/maintained at https://github.com/nabto/nabto-embedded-sdk
# Script version 2020-12-08

function(nabto_version master_version version_var error_var)

  find_program(GIT "git")
  if (NOT GIT)
    set(${error_var} "git executable not found" PARENT_SCOPE)
    return()
  endif()

  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git rev-parse --is-inside-work-tree
    RESULT_VARIABLE IS_GIT_REPOSITORY)

  if (NOT IS_GIT_REPOSITORY EQUAL 0)
    set(${error_var} "directory is not a git repository" PARENT_SCOPE)
    return()
  endif()
  # A git repo, generate version and put it into version_var

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
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND git tag --sort=-committerdate
    OUTPUT_STRIP_TRAILING_WHITESPACE
    OUTPUT_VARIABLE GIT_TAGS ERROR_QUIET)

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
  
  if (GIT_TAG AND NOT GIT_DIRTY)
    # string v4.5.6 -> 4.5.6
    string(SUBSTRING ${GIT_TAG} 1 -1 VERSION)
  elseif (GIT_BRANCH MATCHES "^[0-9].*$")
    # This is a release branch e.g 5.1
    # find the newest release tag matching the release branch and bump that number by one.
    # a release tag is e.g. v5.1.1

    # replace new lines with ; such that it becomes a cmake list.
    string(REPLACE "\r\n" ";" GIT_TAGS ${GIT_TAGS})
    string(REPLACE "\n" ";" GIT_TAGS ${GIT_TAGS})
    # Filter the list such that all tags not matching the branch and the format vmajor.minor.patch is filtered away. 
    set(MATCH_STRING "^v${GIT_BRANCH}\\.[0-9]*$")
    list(FILTER GIT_TAGS INCLUDE REGEX ${MATCH_STRING})
    list(LENGTH GIT_TAGS GIT_TAGS_LENGTH)
    # if the list is empty use the default branch version
    if (GIT_TAGS_LENGTH EQUAL "0") 
      set(VERSION_NUMBER "${GIT_BRANCH}.0")
    else()
      # MAX_TAG is on the form v5.1.1 get the last number and bump it by one.
      list(GET GIT_TAGS 0 NEWEST_TAG)
      set(MATCH_STRING "^v[0-9]+\\.[0-9]+\\.([0-9]+)$")
      string(REGEX MATCH ${MATCH_STRING} VERSION_PATCH_MAX ${NEWEST_TAG})
      set(VERSION_PATCH ${CMAKE_MATCH_1})
      MATH(EXPR VERSION_PATCH "${VERSION_PATCH}+1")
      set(VERSION_NUMBER "${GIT_BRANCH}.${VERSION_PATCH}")
    endif()
    set(VERSION "${VERSION_NUMBER}-rc.${GIT_COUNT}+${GIT_HASH}${GIT_DIRTY}")
  else()
    # A feature branch
    set(VERSION "${master_version}-${GIT_BRANCH}.${GIT_COUNT}+${GIT_HASH}${GIT_DIRTY}")
  endif()

  message("Generated the version: ${VERSION} based on the git repository information")
  set(${version_var} ${VERSION} PARENT_SCOPE)
endfunction()

