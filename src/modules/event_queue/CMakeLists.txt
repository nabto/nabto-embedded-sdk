set(src
  thread_event_queue.c
  nm_event_queue.c
  )

add_library(nm_event_queue "${src}")

target_link_libraries(nm_event_queue np_platform)
