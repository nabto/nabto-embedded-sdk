### Bug fixes
 * Fixed a use-after-free of the hostname during DNS resolution. The core made
   its own copy of the hostname for a resolve, but gave the caller's string to
   the platform's DNS module. If the STUN or basestation hostname was changed
   during the resolve, the old string was freed while the DNS module could
   still be using it. The unix DNS resolver (`nm_unix_dns`), which reads the
   hostname later on its own thread, was affected.
