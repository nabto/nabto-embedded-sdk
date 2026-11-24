### Bug fixes
 * Fixed a memory leak when a CoAP listener is stopped while requests are
   queued on it. The queued requests were answered with 503 but never freed,
   so every such request leaked, including the whole virtual CoAP request
   for requests made on virtual connections.
