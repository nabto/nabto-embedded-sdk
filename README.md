# nabto-embedded-sdk

Nabto embedded SDK

## Building and Testing

mkdir build
cd build
cmake ..
./unit_test


## Components

### `src/platform`

The platform folder contains a platform which is used to run the
unabto core. The platform implements a set of functions which can
schedule events and several interfaces which is used for diverse
features such as udp communication, dns lookups, timestamps etc.

### `src/core`

The core is the nabto communication protocol, the core uses the
platform and implements the core of the embedded nabto communication
system.

### `src/modules`

Modules is the folder where modules for specific targets
exists. Modules can be for encryption, networking, timing, logging
etc.

### `src/dtls`

The DTLS folder implements the dtls used in the core.


