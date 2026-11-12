### Bug fixes
 * Fixed the hostname from a basestation redirect being allocated with
   `calloc()` but freed with the SDK allocator. On platforms which set a custom
   allocator this freed memory the allocator did not own.
