### Security
 * `nabto_device_set_root_certs` now replaces the trusted root certificates,
   as documented, instead of adding to them. Previously the default
   "Nabto Root CA 1" stayed trusted next to the certificates given, so a
   device configured to trust only its own root still accepted basestation
   certificates issued under the default root. If the certificates cannot be
   loaded, no root certificates are trusted until the call succeeds.
