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

### `tcp_tunnel_services.json`

This file defines the services which the tunnel exposes.  A service
consists of a service id, a service type a host as an ip address and a
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

The id and type is sent to the Authorization requests in the IAM
system, such that it is possible to limit a group of users to certain
types of services or specific services.

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

### `tcp_tunnel_policies.json`

This is a file which is generated the first time the TCP Tunnel is
started. It is populated with default IAM policies. If another IAM
configuration is wanted this file can be modified to reflect
that. This file is not updated by the application.

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


### `tcp_tunnel_state.json`

The state of the tcptunnel. This file is updated by the application at
runtime.

### `<product_id>_<device_id>.key`

Key file for the device. If this file does not exists, it's
created. This file is not updated by the application afterwards.

## Usage

First time a TCP Tunnel Device is run several configuration files is
created if they do not exists beforehand. These configuration files
can then be edited such that the device exposes the right services and
has the right policies to enforce access to these.

The first user which is paired with the system gets the role `Admin`
the next users which pairs with the system gets the role `User`.
