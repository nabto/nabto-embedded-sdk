#ifndef NP_LOGGING_DEFINES_H
#define NP_LOGGING_DEFINES_H


// Module definitions
#define NABTO_LOG_MODULE_NONE                    0x00000000ul
#define NABTO_LOG_MODULE_ALL                     0xfffffffful
#define NABTO_LOG_MODULE_UDP                     0x00000001ul
#define NABTO_LOG_MODULE_DNS                     0x00000002ul
#define NABTO_LOG_MODULE_DTLS_CLI                0x00000004ul
#define NABTO_LOG_MODULE_EVENT_QUEUE             0x00000008ul
#define NABTO_LOG_MODULE_CONNECTION              0x00000010ul
#define NABTO_LOG_MODULE_ATTACHER                0x00000020ul
#define NABTO_LOG_MODULE_KEEP_ALIVE              0x00000040ul
#define NABTO_LOG_MODULE_DTLS_SRV                0x00000080ul
#define NABTO_LOG_MODULE_CLIENT_CONNECTION          0x00000100ul
#define NABTO_LOG_MODULE_CLIENT_CONNECTION_DISPATCH 0x00000200ul
#define NABTO_LOG_MODULE_STREAM_MANAGER          0x00000400ul
#define NABTO_LOG_MODULE_STREAM                  0x00000800ul
#define NABTO_LOG_MODULE_UDP_DISPATCH            0x00001000ul
#define NABTO_LOG_MODULE_API                     0x00002000ul
#define NABTO_LOG_MODULE_CORE                    0x00004000ul
#define NABTO_LOG_MODULE_STUN                    0x00008000ul
#define NABTO_LOG_MODULE_RENDEZVOUS              0x00010000ul
#define NABTO_LOG_MODULE_COAP                    0x00020000ul
#define NABTO_LOG_MODULE_TCP                     0x00040000ul
#define NABTO_LOG_MODULE_NETWORK                 0x00080000ul
#define NABTO_LOG_MODULE_TUNNEL                  0x00100000ul
#define NABTO_LOG_MODULE_MDNS                    0x00200000u
#define NABTO_LOG_MODULE_TEST                    0x00400000ul
#define NABTO_LOG_MODULE_PLATFORM                0x00800000ul
#define NABTO_LOG_MODULE_VIRTUAL_CONNECTION      0x01000000ul

// Severity definitions
#define NABTO_LOG_SEVERITY_NONE                  0x00000000ul
#define NABTO_LOG_SEVERITY_ALL                   0xfffffffful
// Individual bit masks
#define NABTO_LOG_SEVERITY_ERROR                 0x00000002ul
#define NABTO_LOG_SEVERITY_WARN                  0x00000004ul
#define NABTO_LOG_SEVERITY_INFO                  0x00000008ul
#define NABTO_LOG_SEVERITY_TRACE                 0x00000010ul
#define NABTO_LOG_SEVERITY_BUFFERS               0x00000020ul
#define NABTO_LOG_SEVERITY_USER1                 0x00000040ul
#define NABTO_LOG_SEVERITY_STATISTICS            0x00000080ul
#define NABTO_LOG_SEVERITY_STATE                 0x00000100ul
// Level bit masks
#define NABTO_LOG_SEVERITY_LEVEL_NONE            NABTO_LOG_SEVERITY_NONE
#define NABTO_LOG_SEVERITY_LEVEL_ERROR           NABTO_LOG_SEVERITY_ERROR
#define NABTO_LOG_SEVERITY_LEVEL_WARN            (NABTO_LOG_SEVERITY_WARN  | NABTO_LOG_SEVERITY_LEVEL_ERROR)
#define NABTO_LOG_SEVERITY_LEVEL_INFO            (NABTO_LOG_SEVERITY_INFO  | NABTO_LOG_SEVERITY_LEVEL_WARN )
#define NABTO_LOG_SEVERITY_LEVEL_TRACE           (NABTO_LOG_SEVERITY_TRACE | NABTO_LOG_SEVERITY_LEVEL_INFO )

#endif // NP_LOGGING_DEFINES_H
