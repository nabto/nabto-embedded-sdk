### Changed
 * `nabto_device_stop()` waits up to 2 seconds for the operations the device
   has started to finish, e.g. a closing connection or the basestation
   attach sending its last DTLS packet, before the platform is stopped. An operation
   which does not finish in time is logged as an error, and the objects using
   it are not freed, rather than freed while in use.

### Bug fixes
 * TCP tunnel connections were freed while an operation on the stream or the
   TCP connection could still be outstanding, e.g. when the device was
   stopped while a tunnel was in use.
 * The libevent UDP and TCP modules could complete an operation twice when a
   socket was aborted while the libevent thread completed the same
   operation, and a TCP read could write into the buffer of a read which had
   already been aborted.
