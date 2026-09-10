# Branches

Integrate against a release branch, not `master`. Support periods follow the
[Nabto security and support
policy](https://www.nabto.com/docs/developer/systems/security-support.html).

| Branch | Latest release | Patched until |
|--------|----------------|---------------|
| `5.15` | `v5.15.1` | Twelve months after 5.16 is released |
| `5.14` | `v5.14.1` | 2027-05-12 |
| `master` | — | Not a release branch |

The current minor release receives security patches; the previous one receives
them for twelve months after the next minor was published; older ones receive
nothing.

`5.0` through `5.12` and `beta4.1` are kept for history and receive no updates.
Any other branch is work in progress — do not integrate against it.
