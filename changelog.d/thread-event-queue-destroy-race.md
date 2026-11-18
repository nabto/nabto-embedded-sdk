### Bug fixes
 * Fixed a race in the thread event queue used by the Linux and macOS
   platforms and by custom platforms built on `thread_event_queue`. An event
   which was cancelled or destroyed just as the event queue thread picked it
   up could still have its callback executed, after the event had been freed.
