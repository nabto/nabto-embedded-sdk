#ifndef NP_ERROR_CODE_H
#define NP_ERROR_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

#define NP_ERROR_CODE_MAPPING(XX)                                       \
    XX(OK, "Ok")                                                        \
        XX(UNKNOWN, "Unknown")                                            \
        XX(NOT_SUPPORTED, "Not supported")                              \
        XX(UDP_SOCKET_CREATION_ERROR, "Udp socket creation error")      \
        XX(UDP_SOCKET_ERROR, "Udp socket error")                        \
        XX(INVALID_SOCKET, "Invalid socket")                            \
        XX(EOF, "End of file")                                          \
        XX(FAILED_TO_SEND_PACKET, "Failed to send packet")              \
        XX(MALFORMED_PACKET, "Malformed packet")                        \
        XX(OUT_OF_CHANNELS, "Out of channels")                          \
        XX(OUT_OF_CONNECTIONS, "Out of connections")                    \
        XX(INVALID_CHANNEL, "Invalid channel")                          \
        XX(INVALID_CONNECTION_ID, "Invalid connection id")              \
        XX(INSUFFICIENT_BUFFER_ALLOCATION, "Insufficient buffer allocation") \
        XX(ALPN_FAILED, "Alpn failed")                                  \
        XX(INVALID_PEER_FINGERPRINT, "Invalid peer fingerprint")        \
        XX(CONNECTION_CLOSING, "Connection closing")                    \
        XX(KEEP_ALIVE_TIMEOUT, "Keep alive timeout")                    \
        XX(SEND_IN_PROGRESS, "Send in progress")                        \
        XX(FUTURE_NOT_RESOLVED, "Future is not resolved yet")           \
        XX(NO_VALID_ENDPOINTS, "No valid endpoints")                    \
        XX(OPERATION_IN_PROGRESS, "Operation in progress")              \
        XX(ABORTED, "Aborted")                                          \
        XX(STOPPED, "Stopped")                                          \
        XX(CLOSED, "Stream closed")                                     \
        XX(RESOURCE_EXISTS, "Resource exists")                          \
        XX(NOT_FOUND, "Not Found")                                      \
        XX(OUT_OF_MEMORY, "Out of memory")                              \
        XX(NOT_IMPLEMENTED, "Not Implemented")                          \
        XX(ACCESS_DENIED, "Access denied")                              \
        XX(STRING_TOO_LONG, "String too long")                          \
        XX(NOT_A_STRING, "Not a string")                                \
        XX(NOT_A_NUMBER, "Not a number")                                \
        XX(INVALID_CONNECTION, "Invalid connection")                    \
        XX(INVALID_ARGUMENT, "Invalid argument")                        \
        XX(IN_USE, "In use")                                            \
        XX(INVALID_STATE, "Invalid State")                              \
        XX(NO_DATA, "No data")                                          \
        XX(OPERATION_STARTED, "Operation started")                      \
        XX(NO_OPERATION, "No operation neccessary")                     \
        XX(AGAIN, "No data available try again later")                  \
        XX(ADDRESS_IN_USE, "Address (port number) already in use")                    \
        XX(NOT_ATTACHED, "Not attached")                                \
        XX(TIMEOUT, "Timeout")                                          \
        XX(BAD_RESPONSE, "Bad response")                                \
        XX(FAILED, "Operation failed, look at the log for more information.") \



#define XX_ERROR(name, _) NABTO_EC_##name,
typedef enum {
    NP_ERROR_CODE_MAPPING(XX_ERROR)
//    NABTO_EC_LAST_ERROR
} np_error_code;
#undef XX_ERROR

const char* np_error_code_to_string(np_error_code ec);

#ifdef __cplusplus
} // extern c
#endif

#endif
