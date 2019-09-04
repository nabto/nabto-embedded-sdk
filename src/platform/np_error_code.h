#ifndef NP_ERROR_CODE_H
#define NP_ERROR_CODE_H

#define NP_ERROR_CODE_MAPPING(XX)                                       \
    XX(OK, "Ok")                                                        \
        XX(FAILED, "Failed")                                            \
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
        XX(INVALID_PACKET_TYPE, "Invalid packet type")                  \
        XX(INSUFFICIENT_BUFFER_ALLOCATION, "Insufficient buffer allocation") \
        XX(ALPN_FAILED, "Alpn failed")                                  \
        XX(INVALID_PEER_FINGERPRINT, "Invalid peer fingerprint")        \
        XX(CONNECTION_CLOSING, "Connection closing")                    \
        XX(KEEP_ALIVE_TIMEOUT, "Keep alive timeout")                    \
        XX(SEND_IN_PROGRESS, "Send in progress")                        \
        XX(API_FUTURE_NOT_READY, "Future not ready")                    \
        XX(NO_VALID_ENDPOINTS, "No valid endpoints")                    \
        XX(OPERATION_IN_PROGRESS, "Operation in progress")              \
        XX(ABORTED, "Aborted")                                          \
        XX(STOPPED, "Stopped")                                          \
        XX(STREAM_CLOSED, "Stream closed")                              \
        XX(STREAM_EOF, "Stream end of file")                            \
        XX(RESOURCE_EXISTS, "Resource exists")                          \
        XX(NOT_FOUND, "Not Found")                                      \
        XX(OUT_OF_MEMORY, "Out of memory")                              \
        XX(NOT_IMPLEMENTED, "Not Implemented")                          \
        XX(IAM_INVALID_POLICY, "IAM invalid policy")                    \
        XX(IAM_TOO_MANY_ATTRIBUTES, "IAM too many attributes")          \
        XX(IAM_STRING_TOO_LONG, "IAM string too long")                  \
        XX(IAM_INVALID_STRING, "IAM invalid string")                    \
        XX(IAM_INVALID_ATTRIBUTES, "IAM invalid attributes")            \
        XX(IAM_INVALID_CONDITIONS, "IAM invalid conditions")            \
        XX(IAM_INVALID_USERS, "IAM invalid users")                      \
        XX(IAM_INVALID_ROLES, "IAM invalid roles")                      \
        XX(IAM_INVALID_POLICIES, "IAM invalid policies")                \
        XX(IAM_INVALID_STATEMENTS, "IAM invalid statements")            \
        XX(IAM_INVALID_ACTIONS, "IAM invalid actions")                  \
        XX(IAM_INVALID_PREDICATES, "IAM invalid predicates")            \
        XX(IAM_DENY, "IAM deny")                                        \
        XX(IAM_NONE, "IAM none")                                        \
        XX(STRING_TOO_LONG, "String too long")                          \
        XX(NOT_A_STRING, "Not a string")                                \
        XX(NOT_A_NUMBER, "Not a number")                                \
        XX(INVALID_CONNECTION, "Invalid connection")                    \
        XX(INVALID_ARGUMENT, "Invalid argument")                        \
        XX(IN_USE, "In use")                                            \
        XX(INVALID_LOG_LEVEL, "Invalid log level") \


#define XX_ERROR(name, _) NABTO_EC_##name,
typedef enum {
    NP_ERROR_CODE_MAPPING(XX_ERROR)
//    NABTO_EC_LAST_ERROR
} np_error_code;
#undef XX_ERROR

/* typedef enum { */
/*     NABTO_EC_OK = 0, */
/*     NABTO_EC_FAILED, */
/*     NABTO_EC_NOT_SUPPORTED, */

/*     NABTO_EC_UDP_SOCKET_CREATION_ERROR, */
/*     NABTO_EC_UDP_SOCKET_ERROR, */
/*     NABTO_EC_INVALID_SOCKET, */

/*     NABTO_EC_EOF, */
/*     NABTO_EC_FAILED_TO_SEND_PACKET, */
/*     NABTO_EC_MALFORMED_PACKET, */
/*     NABTO_EC_OUT_OF_CHANNELS, */
/*     NABTO_EC_OUT_OF_CONNECTIONS, */
/*     NABTO_EC_INVALID_CHANNEL, */
/*     NABTO_EC_INVALID_CONNECTION_ID, */
/*     NABTO_EC_INVALID_PACKET_TYPE, */
/*     NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION, */
/*     NABTO_EC_ALPN_FAILED, */
/*     NABTO_EC_INVALID_PEER_FINGERPRINT, */
/*     NABTO_EC_CONNECTION_CLOSING, */
/*     NABTO_EC_KEEP_ALIVE_TIMEOUT, */
/*     NABTO_EC_SEND_IN_PROGRESS, */
/*     NABTO_EC_API_FUTURE_NOT_READY, */
/*     NABTO_EC_NO_VALID_ENDPOINTS, */
/*     NABTO_EC_OPERATION_IN_PROGRESS, */
/*     NABTO_EC_ABORTED, */
/*     NABTO_EC_STOPPED, */
/*     NABTO_EC_STREAM_CLOSED, */
/*     NABTO_EC_STREAM_EOF, */
/*     NABTO_EC_RESOURCE_EXISTS, */
/*     NABTO_EC_NOT_FOUND, */
/*     NABTO_EC_OUT_OF_MEMORY, */
/*     NABTO_EC_NOT_IMPLEMENTED, */
/*     NABTO_EC_IAM_INVALID_POLICY, */
/*     NABTO_EC_IAM_TOO_MANY_ATTRIBUTES, */
/*     NABTO_EC_IAM_STRING_TOO_LONG, */
/*     NABTO_EC_IAM_INVALID_STRING, */
/*     NABTO_EC_IAM_INVALID_ATTRIBUTES, */
/*     NABTO_EC_IAM_INVALID_CONDITIONS, */
/*     NABTO_EC_IAM_INVALID_USERS, */
/*     NABTO_EC_IAM_INVALID_ROLES, */
/*     NABTO_EC_IAM_INVALID_POLICIES, */
/*     NABTO_EC_IAM_INVALID_STATEMENTS, */
/*     NABTO_EC_IAM_INVALID_ACTIONS, */
/*     NABTO_EC_IAM_INVALID_PREDICATES, */
/*     NABTO_EC_IAM_DENY, */
/*     NABTO_EC_IAM_NONE, */
/*     NABTO_EC_STRING_TOO_LONG, */
/*     NABTO_EC_NOT_A_STRING, */
/*     NABTO_EC_NOT_A_NUMBER, */
/*     NABTO_EC_INVALID_CONNECTION, */
/*     NABTO_EC_INVALID_ARGUMENT, */
/*     NABTO_EC_IN_USE */
/* } np_error_code; */

const char* np_error_code_to_string(np_error_code ec);

#endif
