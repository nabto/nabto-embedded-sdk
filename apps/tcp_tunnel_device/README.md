# TCP Tunnel Device

The TCP Tunnel Device App is an implementation of a TCP Tunnelling
device. The implementation both exists as an reference implementation
for a TCP tunnelling process and a production ready tcp tunnelling
device application which can be installed on a fleet of devices.

TCP Tunnelling in nabto is the concept of having a client which wants
to access a TCP server on a device.

An example could be a device having a HTTP API which the client wants
to consume.

```
TCP Client <-- tcp connection --> TCP Tunnel Client App <-- tcp encapsulated into a nabto stream --> TCP Tunnel Device <-- tcp connection --> TCP Server
```

## Configuration files

The tcptunnel uses several configuration files.

### `tcp_tunnel_device_services.json`

This file defines the services which the tunnel exposes.  A service
consists of a service ID, a service type, a host as an IP address, and a
port number.

Example services file
```
[
  {
    "Id": "mgmt-api",
    "Type": "http",
    "Host": "127.0.0.1",
    "Port": 80
  },
  {
    "Id": "ssh",
    "Type": "ssh",
    "Host": "127.0.0.1",
    "Port": 22
  },
  {
    "Id": "cam1",
    "Type": "rtsp",
    "Host": "192.168.1.1",
    "Port": 554
  }
]
```

The ID and type is sent to the Authorization requests in the IAM
system, such that it is possible to limit a group of users to certain
types of services or specific services.

### `device.json`

The device config is a static file containing the configuration of
device ID, product ID and which server to use. For normal use, the Server will
default to the Nabto basestations and does not need to be provided.

```json
{
  "ProductId": "...",
  "DeviceId": "...",
  "Server": "..."
}
```

### `tcp_tunnel_device_iam_config.json`

This is a file can be generated using the `--init` argument for the
TCP Tunnel, provided from elsewhere for custom IAM configuration, or
modified after creation. It contains IAM policies and roles. This file
is not updated by the application.

Example policy which only accepts connections to Services of type RTSP

```
{
  "Id": "TunnelRTSP",
  "Statements": [
    {
      "Actions": [
        "TcpTunnel:Connect", "TcpTunnel:GetService","TcpTunnel:ListServices"
      ],
      "Effect": "Allow",
      "Conditions": [
        { "stringEquals": { "TcpTunnel:Type": "rtsp" } }
      ]
    }
  ]
}
```

Example Role using the policy:

```
{
  "Id": "Tunneller",
  "Policies": [
    "TunnelRTSP"
  ]
}
```


### `tcp_tunnel_device_iam_state.json`

The state of the TCP Tunnel. This file is also generated with the
`--init` argument to set initial values for state parameters. This
file is updated by the application at runtime.

### `device.key`

Key file for the device. If this file does not exists, it's
created. This file is not updated by the application afterwards.

## Usage

A detailed walk through of using TCP Tunnels in Nabto Edge can be
found on
our
[Documentation site](http://docs.dev.nabto.com/developer/guides/get-started/tunnels/intro.html).

The TCP Tunnel Device should first be run with the `--init` argument
to generate the configuration files described above. If desired, these
files can then be modified so the device exposes the right services
and has the right policies to enforce access to these.

Finally, start the device without the `--init` argument to start it.

The device is now ready to accept connections from clients. The first
connection should be used to pair an Administrator with the
device. This can either be done using `initial local pairing` or
`invite-only password pairing` modes. To connect to the device,
the
[Nabto Client Edge Tunnel](https://github.com/nabto/nabto-client-edge-tunnel) can
be used.
