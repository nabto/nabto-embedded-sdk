### Security
 * Password authentication (SPAKE2) step 1 now spends a token of the rate
   limiter. It was only spent by a failed step 2, so a client could make the
   device do the expensive key computation as fast as it could send requests.
   Step 1 leaves a token for step 2, so a legitimate pairing still completes
   when the limiter is nearly empty.
 * Fixed a possible NULL dereference in password authentication step 2 when the
   connection is gone, and the rate limiter token count can no longer underflow.
