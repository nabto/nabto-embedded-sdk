### Security
 * Fixed a one byte heap over-read when a client sent a stream packet which
   ended right after the stream id. The byte past the packet was read as the
   stream flags. Such packets are now dropped.
