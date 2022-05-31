# Simple Tunnel

The Simple Tunnel device is to be used with the [simple tunnel client](https://github.com/nabto/nabto-client-sdk-examples). This demo
shows how a simple tunnelling example can be created. The example does not include authorization of the tunnelling requests - for a more thorough implementation that includes this, see the [Nabto Edge TCP tunnel app](https://github.com/nabto/nabto-embedded-sdk/tree/master/apps/tcp_tunnel_device).

This device does not use SCTs, and so clients using this device should use a server key with authentication type `NONE`.

## Building

The application is built as part of the SDK, so see the [build instructions](https://github.com/nabto/nabto-embedded-sdk#readme) there.
