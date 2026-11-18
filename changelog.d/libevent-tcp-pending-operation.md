### Bug fixes
 * The libevent TCP module resolved the wrong completion event when
   `np_tcp_async_read` was called while a read was already pending. The
   pending read was completed with `NABTO_EC_OPERATION_IN_PROGRESS`, and later
   completed a second time, while the new read was never completed. Now the new
   read fails with `NABTO_EC_OPERATION_IN_PROGRESS` and the pending read is left
   alone, as in the select_unix module. `np_tcp_async_connect` on a socket
   which is already connecting is rejected the same way, instead of replacing
   the pending connect.
