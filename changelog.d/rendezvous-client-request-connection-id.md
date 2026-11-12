### Bug fixes
 * Fixed rendezvous client requests not being answered. The connection id in
   the request was compared one byte off against the connection ids of the
   open connections, so the device did not recognise the connection and did
   not send a rendezvous response.
