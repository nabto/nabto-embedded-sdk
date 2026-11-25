### Bug fixes
 * Fixed a data race when listeners were created and freed from several
   threads at once. `nabto_device_listener_new()` added the listener to the
   device's list of listeners without holding the device lock, which could
   corrupt the list and crash. `nabto_device_stop()` also walked the list
   without holding the lock while another thread could free a listener.
