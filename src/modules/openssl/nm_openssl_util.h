#ifndef NM_OPENSSL_UTIL_H
#define NM_OPENSSL_UTIL_H

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdbool.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "The OpenSSL DTLS module requires OpenSSL 3.5 or newer"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Calculate the sha256 fingerprint of the public key in a certificate. The
 * fingerprint is the hash of the DER encoded SubjectPublicKeyInfo, the same as
 * the mbedtls and wolfssl modules calculate.
 */
np_error_code nm_openssl_util_fp_from_crt(X509* crt, uint8_t* fp);

np_error_code nm_openssl_create_crt_from_private_key(const char* privateKey, char** crt);

/**
 * take a 32 byte fingerprint buffer as input.
 */
np_error_code nm_openssl_get_fingerprint_from_private_key(const char* privateKey, uint8_t* fingerprint);

np_error_code nm_openssl_util_create_private_key(char** privateKey);

/**
 * Write a private key as a SEC1 (BEGIN EC PRIVATE KEY) PEM string, the format
 * the mbedtls and wolfssl modules write. The string is allocated with the np
 * allocator.
 */
np_error_code nm_openssl_util_private_key_to_pem(EVP_PKEY* key, char** privateKey);

/**
 * Load a PEM encoded private key.
 */
EVP_PKEY* nm_openssl_util_load_private_key(const unsigned char* privateKey, size_t privateKeySize);

/**
 * Load a PEM encoded certificate.
 */
X509* nm_openssl_util_load_certificate(const unsigned char* certificate, size_t certificateSize);

/**
 * Log and clear the OpenSSL error queue in the given log module.
 */
void nm_openssl_util_log_errors(uint32_t logModule);

/**
 * Message callback for ssl objects. Logs the dtls messages if
 * NABTO_DEVICE_DTLS_LOG is defined.
 */
void nm_openssl_util_log_message(uint32_t logModule, int writeP, int contentType, const void* buf, size_t len);

int nm_openssl_sha256(const unsigned char* input, size_t ilen, unsigned char output[32]);

/**
 * Get the dtls mtu, which is the size of a communication buffer as each record
 * is written into one before it is sent. A buffer is allocated to read the
 * size, so call this when the module is set up and cache the result rather
 * than calling it per connection.
 */
np_error_code nm_openssl_util_get_mtu(struct np_platform* pl, uint16_t* mtu);

/**
 * Configure an ssl object for the dtls modules: the mtu is set, OpenSSL does
 * not query the BIO for an mtu, and DTLS 1.2 is the only version.
 */
np_error_code nm_openssl_util_configure_ssl(SSL* ssl, uint16_t mtu);

/**
 * Create a BIO method which hands datagrams to and from the dtls modules. The
 * ctrl callback answers the datagram queries OpenSSL makes on a dtls BIO, read
 * and write are given by the caller and get the connection from BIO_get_data.
 */
BIO_METHOD* nm_openssl_util_create_bio_method(const char* name,
                                              int (*write)(BIO*, const char*, int),
                                              int (*read)(BIO*, char*, int));

/**
 * Read the epoch and sequence number from a DTLS record header. Returns false
 * if the buffer is too short to contain a record header.
 */
bool nm_openssl_util_record_sequence_number(const uint8_t* buffer, size_t bufferSize, uint64_t* seq);

/**
 * Receive available application data from the ssl object. If the return value
 * > 0 the data is returned and must be freed with np_free after use by the
 * caller. Otherwise sslError is set to the SSL_get_error result. If a large
 * enough buffer cannot be allocated the data is discarded and sslError is
 * SSL_ERROR_WANT_READ.
 */
int nm_openssl_recv_data(SSL* ssl, uint8_t** data, int* sslError);

/**
 * Get the expiration of a certificate as a unix timestamp.
 */
np_error_code nm_openssl_util_get_expiration(X509* crt, uint64_t* expiration);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NM_OPENSSL_UTIL_H
