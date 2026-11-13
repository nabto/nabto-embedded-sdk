### Bug fixes
 * Local open and password open pairing now respect `nm_iam_set_max_users`.
   Only creating users through the IAM API was limited, so open pairing
   could add users beyond the limit. A state with more users than the limit
   is rejected when it is loaded, so the device could fail to load its own
   saved state at the next start.
