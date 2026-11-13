### Bug fixes
 * The IAM CoAP endpoint for adding a fingerprint to a user,
   `PUT /iam/users/{user}/fingerprints/{fingerprint}`, now rejects
   fingerprints which are not 64 characters and fingerprint names longer than
   the display name limit, as setting a fingerprint already did. Such values
   were saved and made the saved IAM state fail to load at the next start.
