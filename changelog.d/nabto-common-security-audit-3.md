### Security
 * Updated nabto-common with a third round of security audit fixes. A
   replayed stream syn could previously make a client establish a stream it
   never opened, and a single large stream write queued segments until memory
   ran out, ignoring the congestion window, the receiver's window and the send
   list limit. A large write now queues what the stream can send and reports
   the rest as not written.

### Bug fixes
 * Fixed a number of stream issues found in the same audit: fast retransmit
   stopped working after the stream's logical stamp wrapped, a stream whose
   connection died reported a clean close although sent data was still unacked
   (and an abort although both fins had been exchanged), the syn retransmission
   backoff grew faster than intended, and the read closed event was never
   raised.
 * Fixed CoAP observers being dropped. The server's observe sequence number
   was not wrapped at 24 bits, so an observer was removed after 2^24
   notifications, and the client answered a notification arriving before the
   previous one had been handled with a RST, which cancelled the observation.
