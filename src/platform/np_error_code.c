#include <platform/np_error_code.h>

const char* np_error_code_to_string(np_error_code ec)
{
    switch(ec) {
        case NABTO_EC_OK: return "OK";
        case NABTO_EC_FAILED: return "FAILED";
        case NABTO_EC_UDP_SOCKET_CREATION_ERROR: return "Could not create UDP socket";
        case NABTO_EC_UDP_SOCKET_ERROR: return "UDP socket error";
        case NABTO_EC_INVALID_SOCKET: return "Invalid socket error";
        case NABTO_EC_FAILED_TO_SEND_PACKET: return "Failed to send packet";
        case NABTO_EC_MALFORMED_PACKET: return "Malformed packet error";
        case NABTO_EC_OUT_OF_CHANNELS: return "Out of channels error";
        case NABTO_EC_OUT_OF_CONNECTIONS: return "Out of connections error";
        case NABTO_EC_INVALID_CHANNEL: return "Invalid channel";
        case NABTO_EC_INVALID_CONNECTION_ID: return "Invalid connection ID";
        case NABTO_EC_INVALID_PACKET_TYPE: return "Invalid packet type";
        case NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION: return "Insufficient buffer allocation";
        case NABTO_EC_ALPN_FAILED: return "Application layer protocol negotiation (ALPN) failed";
        case NABTO_EC_INVALID_PEER_FINGERPRINT: return "Invalid peer fingerprint";
        case NABTO_EC_CONNECTION_CLOSING: return "Connection closing";
        case NABTO_EC_KEEP_ALIVE_TIMEOUT:  return "Keep alive timed out";
        case NABTO_EC_SEND_IN_PROGRESS: return "Send in progress";
        case NABTO_EC_API_FUTURE_NOT_READY: return "Future has not yet resolved";
        case NABTO_EC_NO_VALID_ENDPOINTS: return "There where no valid endpoints";
        case NABTO_EC_OPERATION_IN_PROGRESS: return "Operation in progress";
        case NABTO_EC_ABORTED: return "Operation was aborted";
        case NABTO_EC_STREAM_CLOSED: return "Stream closed";
        case NABTO_EC_STREAM_EOF: return "Stream reached end of file";

    }
    return "Unknown error";
}
