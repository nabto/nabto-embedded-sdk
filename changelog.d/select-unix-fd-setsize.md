### Security
 * The select_unix network module now refuses sockets whose file descriptor
   does not fit in an `fd_set`. When the process file descriptor limit is
   above `FD_SETSIZE` (1024), as in many container setups, `FD_SET` and
   `FD_ISSET` on such a descriptor wrote and read outside the `fd_set`. TCP
   tunnel connections opened by clients could push descriptors that high.
