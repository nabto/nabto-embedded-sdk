### Bug fixes
 * Fixed undefined behaviour when trace logging CoAP packets with a Uri-Path or
   Uri-Host option. The option length was passed as a `size_t` where `printf`
   expects an `int` precision, which on 64 bit platforms could print garbage or
   crash.
