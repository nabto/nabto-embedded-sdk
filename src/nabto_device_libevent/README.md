# Nabto Device Libevent

This directory contains the implementation of a Nabto Device Platform based on Libevent. Libevent
enables a cross-platform Nabto Device implementation running on Mac, Linux, and Windows.

## Handling SIGPIPE in TCP tunnels
The Libevent cross-platform abstraction of TCP sockets is used in this implementation. This means
the system call to write to a TCP socket is handled by Libevent. On unix based systems, writing to a
TCP socket can cause the SIGPIPE signal. [Libevent](https://sourceforge.net/p/levent/bugs/148/) will
not attempt to handle SIGPIPE, therefore, Nabto attempts to block this signal as to not crash due to
bad application level TCP traffic. On Linux, `the MSG_NOSIGNAL` cannot be used due to this
abstraction. Instead, on Linux we utilize the fact that POSIX requires the signal to be delivered to
the offending thread by blocking the SIGPIPE signal only in the thread running Libevent. Early
versions of [POSIX](https://groups.google.com/g/comp.unix.programmer/c/dl92lzBXwjw/m/qrBkCEv4YyYJ)
mistakenly defined SIGPIPE to be delivered to the process, not the thread. This means that on some
systems using POSIX.1-2001 or older, the TCP tunnel can cause SIGPIPE which must be handled by the
application running the Nabto Device SDK.

Mac conforms to the POSIX.1-2001 standard, however, on Mac we can utilize the `SO_NOSIGPIPE` socket
option as the native socket can be retrieved from Libevent. Therefore, this implementation should
not cause SIGPIPE on Mac.

Windows does not have SIGPIPE.
