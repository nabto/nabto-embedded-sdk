#include "nm_openssl_util.h"

#include <nabto/nabto_device_config.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

// Strings in the bio are copied with the np allocator into a null terminated
// string.
static char* bio_to_string(BIO* bio)
{
    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || data == NULL) {
        return NULL;
    }
    char* str = np_calloc(1, (size_t)len + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, (size_t)len);
    return str;
}

static np_error_code fp_from_public_key(EVP_PKEY* key, uint8_t* fp)
{
    // The DER encoded SubjectPublicKeyInfo.
    unsigned char* der = NULL;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0) {
        return NABTO_EC_UNKNOWN;
    }
    int ret = nm_openssl_sha256(der, (size_t)len, fp);
    OPENSSL_free(der);
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

np_error_code nm_openssl_util_fp_from_crt(X509* crt, uint8_t* fp)
{
    EVP_PKEY* key = X509_get0_pubkey(crt);
    if (key == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    return fp_from_public_key(key, fp);
}

EVP_PKEY* nm_openssl_util_load_private_key(const unsigned char* privateKey, size_t privateKeySize)
{
    if (privateKeySize > INT_MAX) {
        return NULL;
    }
    BIO* bio = BIO_new_mem_buf(privateKey, (int)privateKeySize);
    if (bio == NULL) {
        return NULL;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return key;
}

X509* nm_openssl_util_load_certificate(const unsigned char* certificate, size_t certificateSize)
{
    if (certificateSize > INT_MAX) {
        return NULL;
    }
    BIO* bio = BIO_new_mem_buf(certificate, (int)certificateSize);
    if (bio == NULL) {
        return NULL;
    }
    X509* crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return crt;
}

static np_error_code set_name(X509_NAME* name)
{
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"nabto", -1, -1, 0) != 1) {
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}

static np_error_code create_crt_inner(X509* crt, EVP_PKEY* key, char** crtPem)
{
    // The certificate has the same contents as the one the mbedtls module
    // creates.
    if (X509_set_version(crt, X509_VERSION_3) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(crt), 1) != 1 ||
        ASN1_TIME_set_string_X509(X509_getm_notBefore(crt), "20010101000000Z") != 1 ||
        ASN1_TIME_set_string_X509(X509_getm_notAfter(crt), "20491231235959Z") != 1 ||
        X509_set_pubkey(crt, key) != 1) {
        return NABTO_EC_UNKNOWN;
    }

    if (set_name(X509_get_subject_name(crt)) != NABTO_EC_OK ||
        set_name(X509_get_issuer_name(crt)) != NABTO_EC_OK) {
        return NABTO_EC_UNKNOWN;
    }

    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    if (ext == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    int ret = X509_add_ext(crt, ext, -1);
    X509_EXTENSION_free(ext);
    if (ret != 1) {
        return NABTO_EC_UNKNOWN;
    }

    if (X509_sign(crt, key, EVP_sha256()) <= 0) {
        return NABTO_EC_UNKNOWN;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    np_error_code ec = NABTO_EC_OK;
    if (PEM_write_bio_X509(bio, crt) != 1) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        *crtPem = bio_to_string(bio);
        if (*crtPem == NULL) {
            ec = NABTO_EC_OUT_OF_MEMORY;
        }
    }
    BIO_free(bio);
    return ec;
}

np_error_code nm_openssl_create_crt_from_private_key(const char* privateKey, char** crt)
{
    *crt = NULL;
    EVP_PKEY* key = nm_openssl_util_load_private_key((const unsigned char*)privateKey, strlen(privateKey));
    if (key == NULL) {
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_UNKNOWN;
    }
    X509* x509 = X509_new();
    np_error_code ec = NABTO_EC_OUT_OF_MEMORY;
    if (x509 != NULL) {
        ec = create_crt_inner(x509, key, crt);
        X509_free(x509);
    }
    if (ec != NABTO_EC_OK) {
        nm_openssl_util_log_errors(LOG);
    }
    EVP_PKEY_free(key);
    return ec;
}

np_error_code nm_openssl_get_fingerprint_from_private_key(const char* privateKey, uint8_t* fingerprint)
{
    EVP_PKEY* key = nm_openssl_util_load_private_key((const unsigned char*)privateKey, strlen(privateKey));
    if (key == NULL) {
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_UNKNOWN;
    }
    np_error_code ec = fp_from_public_key(key, fingerprint);
    EVP_PKEY_free(key);
    return ec;
}

np_error_code nm_openssl_util_private_key_to_pem(EVP_PKEY* key, char** privateKey)
{
    *privateKey = NULL;
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    np_error_code ec = NABTO_EC_UNKNOWN;
    // The type-specific structure is SEC1 for EC keys.
    OSSL_ENCODER_CTX* ectx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM", "type-specific", NULL);
    if (ectx != NULL && OSSL_ENCODER_CTX_get_num_encoders(ectx) > 0 &&
        OSSL_ENCODER_to_bio(ectx, bio) == 1) {
        *privateKey = bio_to_string(bio);
        ec = (*privateKey == NULL) ? NABTO_EC_OUT_OF_MEMORY : NABTO_EC_OK;
    }
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(bio);
    return ec;
}

np_error_code nm_openssl_util_create_private_key(char** privateKey)
{
    *privateKey = NULL;
    EVP_PKEY* key = EVP_EC_gen("P-256");
    if (key == NULL) {
        nm_openssl_util_log_errors(LOG);
        return NABTO_EC_UNKNOWN;
    }
    np_error_code ec = nm_openssl_util_private_key_to_pem(key, privateKey);
    EVP_PKEY_free(key);
    return ec;
}

static int log_error_cb(const char* str, size_t len, void* u)
{
    uint32_t module = *(uint32_t*)u;
    NABTO_LOG_ERROR(module, "OpenSSL: %.*s", (int)len, str);
    return 1;
}

void nm_openssl_util_log_errors(uint32_t logModule)
{
    ERR_print_errors_cb(&log_error_cb, &logModule);
}

#if defined(NABTO_DEVICE_DTLS_LOG)
static const char* content_type_name(int contentType)
{
    switch (contentType) {
        case SSL3_RT_CHANGE_CIPHER_SPEC: return "change_cipher_spec";
        case SSL3_RT_ALERT: return "alert";
        case SSL3_RT_HANDSHAKE: return "handshake";
        case SSL3_RT_APPLICATION_DATA: return "application_data";
        case SSL3_RT_HEADER: return "record_header";
        case SSL3_RT_INNER_CONTENT_TYPE: return "inner_content_type";
        default: return "unknown";
    }
}
#endif

void nm_openssl_util_log_message(uint32_t logModule, int writeP, int contentType, const void* buf, size_t len)
{
#if defined(NABTO_DEVICE_DTLS_LOG)
    const uint8_t* b = buf;
    if (contentType == SSL3_RT_HANDSHAKE && len > 0) {
        NABTO_LOG_TRACE(logModule, "%s %s type %u, %u bytes", writeP ? "sent" : "received", content_type_name(contentType), b[0], (unsigned)len);
    } else if (contentType == SSL3_RT_ALERT && len >= 2) {
        NABTO_LOG_TRACE(logModule, "%s alert level %u, description %u", writeP ? "sent" : "received", b[0], b[1]);
    } else {
        NABTO_LOG_TRACE(logModule, "%s %s, %u bytes", writeP ? "sent" : "received", content_type_name(contentType), (unsigned)len);
    }
#else
    (void)logModule;
    (void)writeP;
    (void)contentType;
    (void)buf;
    (void)len;
#endif
}

int nm_openssl_sha256(const unsigned char* input, size_t ilen, unsigned char output[32])
{
    if (EVP_Digest(input, ilen, output, NULL, EVP_sha256(), NULL) != 1) {
        return -1;
    }
    return 0;
}

np_error_code nm_openssl_util_get_mtu(struct np_platform* pl, uint16_t* mtu)
{
    struct np_communication_buffer* buf = pl->buf.allocate();
    if (buf == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    size_t size = pl->buf.size(buf);
    pl->buf.free(buf);
    // Leave room for the connection id header which is put in front of
    // datagrams on client connections.
    if (size <= NP_DTLS_CONNECTION_ID_HEADER_SIZE) {
        return NABTO_EC_FAILED;
    }
    *mtu = (uint16_t)(size - NP_DTLS_CONNECTION_ID_HEADER_SIZE);
    return NABTO_EC_OK;
}

np_error_code nm_openssl_util_configure_ssl(SSL* ssl, uint16_t mtu)
{
    if (SSL_set_min_proto_version(ssl, DTLS1_2_VERSION) != 1 ||
        SSL_set_max_proto_version(ssl, DTLS1_2_VERSION) != 1) {
        return NABTO_EC_FAILED;
    }
    // The BIO has no socket to query an mtu from. The mtu is the size of a
    // datagram, so a record and its header fit in a communication buffer.
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    // Returns the mtu on success and 0 if it is too small.
    if (SSL_set_mtu(ssl, mtu) <= 0) {
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;
}

static long bio_ctrl(BIO* bio, int cmd, long num, void* ptr)
{
    (void)bio;
    (void)num;
    (void)ptr;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            // Datagrams are handed to the sender when they are written.
            return 1;
        case BIO_CTRL_DGRAM_QUERY_MTU:
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            // The mtu set on the ssl object is the datagram size without any
            // overhead.
            return 0;
        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
            return 0;
        default:
            return 0;
    }
}

static int bio_create(BIO* bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

BIO_METHOD* nm_openssl_util_create_bio_method(const char* name,
                                              int (*write)(BIO*, const char*, int),
                                              int (*read)(BIO*, char*, int))
{
    BIO_METHOD* method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, name);
    if (method == NULL) {
        return NULL;
    }
    if (BIO_meth_set_write(method, write) != 1 ||
        BIO_meth_set_read(method, read) != 1 ||
        BIO_meth_set_ctrl(method, bio_ctrl) != 1 ||
        BIO_meth_set_create(method, bio_create) != 1) {
        BIO_meth_free(method);
        return NULL;
    }
    return method;
}

bool nm_openssl_util_record_sequence_number(const uint8_t* buffer, size_t bufferSize, uint64_t* seq)
{
    // DTLS record header: type (1), version (2), epoch (2), sequence number
    // (6). Epoch and sequence number are bytes 3-10.
    if (bufferSize < 11) {
        return false;
    }
    const uint8_t* b = buffer + 3;
    *seq = (((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
            ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
            ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
            ((uint64_t)b[6] << 8) | ((uint64_t)b[7]));
    return true;
}

int nm_openssl_recv_data(SSL* ssl, uint8_t** data, int* sslError)
{
    uint8_t smallRecvBuffer[16];
    // first recv a few bytes and then retrieve the rest of the record or
    // discard it if a buffer large enough cannot be allocated.
    int ret = SSL_read(ssl, smallRecvBuffer, (int)sizeof(smallRecvBuffer));
    if (ret <= 0) {
        *sslError = SSL_get_error(ssl, ret);
        return ret;
    }

    size_t smallRecvLength = (size_t)ret;
    int remaining = SSL_pending(ssl);
    size_t totalRecvLength = smallRecvLength;

    uint8_t* recvBuffer = np_calloc(1, smallRecvLength + (size_t)remaining);
    if (recvBuffer == NULL) {
        // discard the rest of the record
        while (SSL_pending(ssl) > 0) {
            if (SSL_read(ssl, smallRecvBuffer, (int)sizeof(smallRecvBuffer)) <= 0) {
                break;
            }
        }
        // As if no data was available.
        *sslError = SSL_ERROR_WANT_READ;
        return -1;
    }

    memcpy(recvBuffer, smallRecvBuffer, smallRecvLength);
    if (remaining > 0) {
        ret = SSL_read(ssl, recvBuffer + smallRecvLength, remaining);
        if (ret <= 0) {
            *sslError = SSL_get_error(ssl, ret);
            np_free(recvBuffer);
            return ret;
        }
        totalRecvLength += (size_t)ret;
    }
    *data = recvBuffer;
    return (int)totalRecvLength;
}

np_error_code nm_openssl_util_get_expiration(X509* crt, uint64_t* expiration)
{
    const ASN1_TIME* notAfter = X509_get0_notAfter(crt);
    ASN1_TIME* epoch = ASN1_TIME_set(NULL, 0);
    if (notAfter == NULL || epoch == NULL) {
        ASN1_TIME_free(epoch);
        return NABTO_EC_UNKNOWN;
    }
    int days = 0;
    int seconds = 0;
    int ret = ASN1_TIME_diff(&days, &seconds, epoch, notAfter);
    ASN1_TIME_free(epoch);
    if (ret != 1) {
        return NABTO_EC_UNKNOWN;
    }
    int64_t t = (int64_t)days * 86400 + seconds;
    if (t < 0) {
        return NABTO_EC_UNKNOWN;
    }
    *expiration = (uint64_t)t;
    return NABTO_EC_OK;
}
