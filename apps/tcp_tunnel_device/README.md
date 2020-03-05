# TCP Tunnel Device

The TCP Tunnel App is a device which acts as a tcp tunnelling daemon.

  * A generic tcp client e.g. a webbrowser connects to a tcp listener on the TCP Tunnel Client App.
  * The TCP Tunnel Client App encapsulates the tcp connection in a nabto connection to the TCP Tunnel Device.
  * The TCP Tunnel Device de-encapsulates the data stream and sends
    the tcp data to the generic tcp server.

```
TCP Client <-- tcp connection --> TCP Tunnel Client App <-- tcp encapsulated into a nabto stream --> TCP Tunnel Device <-- tcp connection --> TCP Server
```

## Configuration files

The tcptunnel uses several configuration files.

### `device_config.json`

The device config is a static file containing the configuration like
device id and which server to use.

```json
{
  "ProductId": "...",
  "DeviceId": "...",
  "Server": "...",
  "Client": {
    "ServerKey": "...",
    "ServerUrl": "..."
  }
}
```

### `tcptunnel_policies.json`

This is a file which is generated the first time the TCP Tunnel is
started. It is populated with default IAM policies. If another IAM
configuration is wanted this file can be modified to reflect
that. This file is not updated by the application.

TODO: document how to limit access to specific hosts and ports.

### `tcptunnel_state.json`

The state of the tcptunnel. This file is updated by the application on
runtime.

### `<product_id>_<device_id>.key`

Key file for the device. If this file does not exists, it's
created. This file is not updated by the application afterwards.

## Usage

The TCP Tunnel Device uses the Fingerprint IAM module. This means a
client need to use a supported pairing method to be paired with the
device in first place.

TODO: make this section better.
