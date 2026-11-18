### Bug fixes
 * Fixed a crash in the unix DNS resolver (`nm_unix_dns`) when it was stopped
   while DNS requests were still queued. Stopping the resolver dereferenced a
   NULL pointer instead of failing the queued requests with
   `NABTO_EC_STOPPED`. The resolver is used by the select_unix platform
   integration example and the platform integration steps.
