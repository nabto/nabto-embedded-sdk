### Bug fixes
 * Local initial pairing now refuses a client whose fingerprint already
   belongs to another user, with 409, as the other pairing modes do.
   Previously the fingerprint was added to the initial user as well, so one
   fingerprint could belong to two users and which user a connection was
   treated as depended on the order of the users.
