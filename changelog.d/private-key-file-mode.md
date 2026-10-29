### Security
 * Files written by the POSIX file system module, such as the private key of the
   device, were created with the default mode, typically readable by all users.
   They are now created with mode 0600 and are written to a temporary file which
   is renamed over the target, so a crash while writing no longer leaves a
   truncated file. An existing key file keeps its old permissions until it is
   written again.
