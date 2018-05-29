
enum application_data_type {
    ATTACH_DISPATCH = 1,
    ATTACH = 2,
    RELAY = 3
};

enum attach_dispatch_content_type {
    ATTACH_DISPATCH_REQUEST = 1,
    ATTACH_DISPATCH_REDIRECT = 2,
    ATTACH_DISPATCH_RESPONSE = 3
};

enum attach_content_type {
    ATTACH_DEVICE_HELLO = 1,
    ATTACH_SERVER_HELLO = 2
};

enum extension_type {
    UDP_DNS_EP = 0x0001,
    UDP_IPV4_EP = 0x0002,
    UDP_IPV6_EP = 0x0003,
    SUPPORTED_VERSIONS = 0x0004
};
