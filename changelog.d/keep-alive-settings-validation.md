### Security
 * Fixed a division by zero, and a keep alive timer spinning the event loop,
   when the basestation sent keep alive settings with a zero or very small
   retry interval. The settings were also truncated to 32 bit before use. Keep
   alive settings which are out of range are now ignored and the defaults are
   kept.
