find_path(LIBEVENT_INCLUDE_DIRS event2/event.h)

find_library(EVENT_LIBRARY event)
find_library(CORE_LIBRARY event_core)
find_library(EXTRA_LIBRARY event_extra)
find_library(PTHREADS_LIBRARY event_pthreads)

set(LIBEVENT_LIBRARIES "${EVENT_LIBRARY}" "${CORE_LIBRARY}" "${EXTRA_LIBRARY}" "${PTHREADS_LIBRARY}")

#message(FATAL_ERROR "${LIBEVENT_LIBRARIES}")

if(CORE_LIBRARY)
  add_library(libevent::core STATIC IMPORTED)
  target_link_libraries(libevent::core INTERFACE "${CORE_LIBRARY}")
  set_target_properties(libevent::core PROPERTIES IMPORTED_LOCATION "${CORE_LIBRARY}")
  target_include_directories(libevent::core INTERFACE "${LIBEVENT_INCLUDE_DIRS}")

  add_library(libevent::extra STATIC IMPORTED)
  target_link_libraries(libevent::extra INTERFACE "${EXTRA_LIBRARY}")
  set_target_properties(libevent::extra PROPERTIES IMPORTED_LOCATION "${EXTRA_LIBRARY}")
  target_include_directories(libevent::extra INTERFACE "${LIBEVENT_INCLUDE_DIRS}")

  add_library(libevent::pthreads STATIC IMPORTED)
  target_link_libraries(libevent::pthreads INTERFACE "${PTHREADS_LIBRARY}")
  set_target_properties(libevent::pthreads PROPERTIES IMPORTED_LOCATION "${PTHREADS_LIBRARY}")
  target_include_directories(libevent::pthreads INTERFACE "${LIBEVENT_INCLUDE_DIRS}")


  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LIBEVENT DEFAULT_MSG
    LIBEVENT_INCLUDE_DIRS EVENT_LIBRARY CORE_LIBRARY EXTRA_LIBRARY PTHREADS_LIBRARY)

  mark_as_advanced(LIBEVENT_INCLUDE_DIRS EVENT_LIBRARY CORE_LIBRARY EXTRA_LIBRARY PTHREADS_LIBRARY)

endif()
