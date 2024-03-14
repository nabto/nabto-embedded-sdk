# Running Mallocfail on the SDK

## Understanding Mallocfail
When running an executable with mallocfail, when the executable tries to allocate memory, mallocfail notes down a hash of the stack trace and fails the allocation by returning NULL. The next time the executable tries to allocate memory with the same stack trace hash, it will be allocated successfully. Stack trace hashes are saved to the `./mallocfail_hashes` file, so if an allocation failure causes the executable to exit, running the executable again will not cause mallocfail fail that allocation again.

## Building

first install dependencies:

```
sudo apt-get install libxxhash-dev
```

```
git clone https://github.com/ianlancetaylor/libbacktrace.git
cd libbacktrace
./configure
sudo make install
```

Then build mallocfail
```
git clone https://github.com/nabto/mallocfail.git
cd mallocfail
make
```
The mallocfail directory should now contain the `mallocfail.so` file. We need to refer to this file when running the device.

## Running the TCP Tunnel with mallocfail

Firstly, build a TCP Tunnel device with debug symbols.

Then running is simply done by loading the .so file when running an executable like this:

```
MALLOCFAIL_DEBUG=1 LD_PRELOAD=/workspace/mallocfail/mallocfail.so ./apps/tcp_tunnel_device/tcp_tunnel_device
```

## Testing the TCP Tunnel App for QA
Even though the steps below makes several optimizations to speed up this test, it will still be quite slow.

1. Run the TCP Tunnel app without mallocfail to ensure it can attach to the basestation and that you can access a http server through it. `./apps/tcp_tunnel_device/tcp_tunnel_device`
2. Check `CMakeCache.txt` to ensure you are building with debug symbols
3. When an allocation error causes an attach attempt to fail, it wil wait 10s to retry. Change `src/core/nc_attacher.c:22` to eg. 100ms so testing will not take forever.
4. Build the tcp tunnel
5. ensure you have `ulimit -c unlimited` to get core dumps.
6. Some times an allocation error causing a DTLS connection to fail will result in DTLS waiting for a timeout. Since Mbedtls makes a lot of allocations, this can be very slow. To speed things up, we ca assume mbedtls handle allocation errors properly and run the test with `MALLOCFAIL_IGNORE=mbedtls`
7. Run the device. The first many allocation errors will cause the device to exit before it has started. To speed this up, you can use a bash script like below to rerun the executable until it returns a signal return code (eg. 139 for segmentation fault).
8. If the device crashes do:
    * run `gdb ./apps/tcp_tunnel_device/tcp_tunnel_device core` to debug  and fix the issue.
    * Remove the last eg. 20 lines of the `mallocfail_hashes` file (eg.: `head -n -20 mallocfail_hashes > mallocfail_hashes2 && mv mallocfail_hashes2 mallocfail_hashes`)
    * rerun the test to see if your fix worked.
9. repeat step 7-8 until the device is attached to the basestation.
10. From this dir, to to the test-client dir: `cd test-client`
11. Run `npm install`
12. Connect with the test client `ts-node app.ts`. This will:
    * Connect to the device.
    * Open a http tcp tunnel.
    * get the http page
    * close down
    * repeat 10 times
13. Repeat step 12 until the client completes everything successfully. If the device crashes, go to step 8.

### example mallocfail bash script
This script simply reruns the device indefinitely. This can be annoying to stop so beware.
```
#!/bin/bash

while true; do

MALLOCFAIL_IGNORE=mbedtls MALLOCFAIL_DEBUG=1 LD_PRELOAD=/workspace/build-scripts/mallocfail/mallocfail/mallocfail.so ./apps/tcp_tunnel_device/tcp_tunnel_device -H ./tunnelHome

if [ $? -gt 4 ]; then
    break
fi
echo " ------ Next Run ------"
done
```

