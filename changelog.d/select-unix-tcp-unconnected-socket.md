### Bug fixes
 * Fixed a crash in the select based unix platform (`nm_select_unix`) when a
   TCP socket had been created but not yet connected while the select loop
   handled other sockets. The socket's invalid file descriptor was passed to
   `FD_ISSET`, which aborts the process with "bit out of range 0 - FD_SETSIZE
   on fd_set" when built with `_FORTIFY_SOURCE`, the default on Ubuntu.
