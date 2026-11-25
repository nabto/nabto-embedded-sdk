### Bug fixes
 * Fixed a data race in the libevent DNS resolver which could corrupt its list
   of outstanding requests. A new request was added to the list without the
   lock which protects it, while an answered request was removed from it on the
   libevent thread.
