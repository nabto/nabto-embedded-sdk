### Security
 * Fixed a STUN send being started while the previous one was still in
   progress. Any UDP packet which looked like STUN, arriving at the device
   while a STUN analysis was sending, reused the send buffer and completion
   event of the outstanding send. With lifetime checks enabled this aborted
   the device. On a platform with asynchronous UDP sends the buffer was
   overwritten while it was being sent.
