### Bug fixes
 * Fixed a memory leak in IAM password open pairing. A client which sent a
   `Password` in the request (the unsupported 5.1 pairing flow) leaked the
   client fingerprint on every request.
