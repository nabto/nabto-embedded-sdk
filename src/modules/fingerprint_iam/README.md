## Fingerprint pairing

fingerprint pairing module which uses the cpp iam module and
implements the function needed to check iam access for the nabto core
and applications.

The pairing can happen based on a one time password or a button press.

Users is looked up in the users table based on fingerprints. If no
such fingerprint exists they are given a default unpaired role.
