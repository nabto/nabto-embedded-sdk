Simple push device

Features:
  * starts and attaches
  * uses the iam module to provide a user database with open local pairing
  * uses the iam module to store push tokens.

Since the simple push device utilizes the IAM module, server keys of any authentication type can be
used with this example.

Use case:
  1. clients discover the device
  2. clients pairs with the device
  3. clients configure push tokens and categories
  4. clients receive push notifications
  5. clients receive test push notifications.
