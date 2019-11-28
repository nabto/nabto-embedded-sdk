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

### Tcp Echo server

The device includes a tcp echo server which listens on port 58165

The device includes a tcp http server which listens on port 29281
