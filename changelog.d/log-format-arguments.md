### Bug fixes
 * Fixed a crash in `nm_select_unix_init` when `pipe()` failed. The error was
   logged with `%s` but given `errno`, an `int`, so the logger read it as a
   string pointer. The error is now logged with `strerror(errno)`.
 * Fixed log statements whose arguments did not match their format strings.
   Stream IDs and the SCT version are 64 bit and were printed with `%u`, which
   prints the wrong value and shifts any later arguments on 32 bit targets.
   `size_t` values passed for `%d`/`%u` are now cast. The UDP receive error log
   in the core read an argument that was never passed, and now prints the error
   code.
