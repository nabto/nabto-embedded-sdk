### Bug fixes
 * When sending a keep-alive request or response failed immediately, for
   example while the DTLS connection was not ready, the keep-alive stayed
   marked as sending. No further keep-alives were sent or answered on the
   connection or the basestation attachment, and keep-alive timeouts were no
   longer detected.
