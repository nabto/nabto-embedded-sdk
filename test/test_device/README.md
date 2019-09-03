## Test Device

The test device is a device which can used with nabto to test
different functionality.

### Stream Echo Server

The test device has a stream echo server. When a client opens a stream
it echoes all the received data back to the client.

The echo server has the type 42.

### Coap Server

The device has a coap server which have a POST and a GET endpoint.

CoAP POST /test/post
CoAP GET /test/get
