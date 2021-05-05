#include "nc_spake2.h"
#include "nc_client_connection.h"
#include <platform/np_logging.h>


#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <string.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION

/**
 * Definitions of the curve points M and N, which is used in the
 * spake2 algorithm.
 */
const uint8_t Mdata[] = {  0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20 };

static uint8_t Ndata[] = { 0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7 };

static int hashLength(mbedtls_md_context_t* mdCtx, uint32_t val);
static int hashData(mbedtls_md_context_t* mdCtx, uint8_t* data, size_t dataLength);
static int hashPoint(mbedtls_md_context_t* mdCtx, mbedtls_ecp_group* grp, mbedtls_ecp_point* p);
static int hashMpi(mbedtls_md_context_t* mdCtx, mbedtls_mpi* n);

static int calculateKey(mbedtls_ecp_group* g, mbedtls_ecp_point* T, const char* password, uint8_t fingerprintClient[32], uint8_t fingerprintDevice[32], mbedtls_ecp_point* S, uint8_t* key);

void newTokenEvent(void* data);

void nc_spake2_init(struct nc_spake2_module* module, struct np_platform* pl)
{
    module->passwordRequestHandler = NULL;
    module->passwordRequestHandlerData = NULL;
    module->spake21 = NULL;
    module->spake22 = NULL;
    module->tokens = NC_SPAKE2_MAX_TOKENS;
    module->pl = pl;
    np_event_queue_create_event(&pl->eq, &newTokenEvent, module, &module->tbEvent);
}

void nc_spake2_deinit(struct nc_spake2_module* config)
{
    np_event_queue_destroy_event(&config->pl->eq, config->tbEvent);
}

void nc_spake2_clear_password_request_callback(struct nc_spake2_module* module)
{
    module->passwordRequestHandler = NULL;
    module->passwordRequestHandlerData = NULL;
}

np_error_code nc_spake2_set_password_request_callback(struct nc_spake2_module* module, nc_spake2_password_request_handler passwordRequestFunction, void* data)
{
    if (module->passwordRequestHandler != NULL) {
        return NABTO_EC_IN_USE;
    }
    module->passwordRequestHandler = passwordRequestFunction;
    module->passwordRequestHandlerData = data;
    return NABTO_EC_OK;
}

struct nc_spake2_password_request* nc_spake2_password_request_new()
{
    struct nc_spake2_password_request* passwordRequest = calloc(1, sizeof(struct nc_spake2_password_request));
    if (passwordRequest == NULL) {
        return NULL;
    }
    mbedtls_ecp_group_init(&passwordRequest->grp);
    mbedtls_ecp_point_init(&passwordRequest->T);
    mbedtls_ecp_group_load(&passwordRequest->grp, MBEDTLS_ECP_DP_SECP256R1);
    return passwordRequest;
}

void nc_spake2_password_request_free(struct nc_spake2_password_request* passwordRequest)
{
    if (passwordRequest == NULL) {
        return;
    }
    mbedtls_ecp_point_free(&passwordRequest->T);
    mbedtls_ecp_group_free(&passwordRequest->grp);
    free(passwordRequest);
}

void nc_spake2_password_ready(struct nc_spake2_password_request* req, const char* password)
{

    struct nabto_coap_server_request* coap = req->coapRequest;
    struct nc_client_connection* connection = (struct nc_client_connection*)nabto_coap_server_request_get_connection(coap);

    if (connection == NULL) {
        nabto_coap_server_send_error_response(coap, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
    } else {
        uint8_t fingerprintClient[32];
        uint8_t fingerprintDevice[32];

        nc_client_connection_get_client_fingerprint(connection, fingerprintClient);
        nc_client_connection_get_device_fingerprint(connection, fingerprintDevice);

        mbedtls_ecp_point S;
        mbedtls_ecp_point_init(&S);

        int status = 0;
        mbedtls_ecp_group grp;
        mbedtls_ecp_group_init(&grp);
        status |= mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

        status |= calculateKey(&grp, &req->T, password, fingerprintClient, fingerprintDevice, &S, connection->spake2Key);
        size_t olen;
        uint8_t buffer[256];
        status |= mbedtls_ecp_point_write_binary (&grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buffer, sizeof(buffer));

        if (status == 0) {
            connection->hasSpake2Key = true;
            strcpy(connection->username, req->username);
            // respond with S
            nabto_coap_server_response_set_payload(coap, buffer, olen);
            nabto_coap_server_response_set_code_human(coap, 201);
            nabto_coap_server_response_set_content_format(coap, NABTO_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);
            nabto_coap_server_response_ready(coap);
        } else {
            nabto_coap_server_send_error_response(coap, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        }


        mbedtls_ecp_point_free(&S);
        mbedtls_ecp_group_free(&grp);
    }

    nabto_coap_server_request_free(coap);
    nc_spake2_password_request_free(req);
}

void newTokenEvent(void* data)
{
    struct nc_spake2_module* module = (struct nc_spake2_module*)data;
    module->tokens++;
    if (module->tokens < NC_SPAKE2_MAX_TOKENS) { // if not at max, add another token later
        np_event_queue_post_timed_event(&module->pl->eq, module->tbEvent, NC_SPAKE2_TOKEN_INTERVAL);
    }
}

void nc_spake2_spend_token(struct nc_spake2_module* module)
{
    if (module->tokens == NC_SPAKE2_MAX_TOKENS) { // if not at max, the event is already scheduled
        np_event_queue_post_timed_event(&module->pl->eq, module->tbEvent, NC_SPAKE2_TOKEN_INTERVAL);
    }
    module->tokens--;
}


/**
 * Calculate S and the key.
 */
int calculateKey(mbedtls_ecp_group* grp, mbedtls_ecp_point* T, const char* password, uint8_t fingerprintClient[32], uint8_t fingerprintDevice[32], mbedtls_ecp_point* S, uint8_t* key)
{
    mbedtls_ecp_point M;
    mbedtls_ecp_point N;
    mbedtls_ecp_point Y;
    mbedtls_ecp_point K;

    mbedtls_mpi y;
    mbedtls_mpi w;

    mbedtls_ecp_point_init(&M);
    mbedtls_ecp_point_init(&N);
    mbedtls_ecp_point_init(&Y);
    mbedtls_ecp_point_init(&K);

    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&w);

    int status = 0;
    status |= mbedtls_ecp_point_read_binary(grp, &M, Mdata, sizeof(Mdata));
    status |= mbedtls_ecp_point_read_binary(grp, &N, Ndata, sizeof(Ndata));

    uint8_t passwordHash[32];

    {
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ctr_drbg_init( &ctr_drbg );
        mbedtls_entropy_init( &entropy );
        status |= mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

        status |= mbedtls_ecp_gen_keypair( grp, &y, &Y, mbedtls_ctr_drbg_random, &ctr_drbg);

        if (password == NULL) {
            status |= mbedtls_ctr_drbg_random(&ctr_drbg, passwordHash, 32);
        } else {
            status |= mbedtls_sha256_ret((const uint8_t*)password, strlen(password), passwordHash, 0);
        }
        status |= mbedtls_mpi_read_binary(&w, passwordHash, sizeof(passwordHash));

        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }

    {
        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        status |= mbedtls_mpi_lset(&tmp, 1);

        // S = N*w + Y*1
        status |= mbedtls_ecp_muladd(grp, S, &w, &N, &tmp, &Y);

        // K = y*(T-w*M) = y*T - y*w*M

        // tmp = -w*y mod n
        status |= mbedtls_mpi_lset(&tmp, -1);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &y);
        status |= mbedtls_mpi_mul_mpi(&tmp, &tmp, &w);
        status |= mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->N);

        // K = y*T+((-y*w)*M)
        status |= mbedtls_ecp_muladd(grp, &K, &y, T, &tmp, &M);

        mbedtls_mpi_free(&tmp);
    }

    {
        mbedtls_md_context_t mdCtx;
        mbedtls_md_init(&mdCtx);
        status |= mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        status |= mbedtls_md_starts(&mdCtx);

        status |= hashData(&mdCtx, fingerprintClient, 32);
        status |= hashData(&mdCtx, fingerprintDevice, 32);

        status |= hashPoint(&mdCtx, grp, T);
        status |= hashPoint(&mdCtx, grp, S);
        status |= hashPoint(&mdCtx, grp, &K);

        status |= hashMpi(&mdCtx, &w);

        status |= mbedtls_md_finish(&mdCtx, key);

        mbedtls_md_free(&mdCtx);
    }

    mbedtls_ecp_point_free(&M);
    mbedtls_ecp_point_free(&N);
    mbedtls_ecp_point_free(&Y);
    mbedtls_ecp_point_free(&K);

    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&w);

    return status;
}

int hashLength(mbedtls_md_context_t* mdCtx, uint32_t val)
{
    uint8_t b[4];
    b[0] = (uint8_t)(val >> 24);
    b[1] = (uint8_t)(val >> 16);
    b[2] = (uint8_t)(val >> 8);
    b[3] = (uint8_t)val;

    return mbedtls_md_update(mdCtx, b, 4);
}

int hashData(mbedtls_md_context_t* mdCtx, uint8_t* data, size_t dataLength)
{
    int status = 0;
    status |= hashLength(mdCtx, dataLength);
    status |= mbedtls_md_update(mdCtx, data, dataLength);
    return status;
}

int hashPoint(mbedtls_md_context_t* mdCtx, mbedtls_ecp_group* grp, mbedtls_ecp_point* p)
{
    size_t olen;
    uint8_t buffer[256];
    int status = 0;
    status |= mbedtls_ecp_point_write_binary (grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buffer, sizeof(buffer));
    status |= hashData(mdCtx, buffer, olen);
    return status;
}

int hashMpi(mbedtls_md_context_t* mdCtx, mbedtls_mpi* n)
{
    size_t s = mbedtls_mpi_size(n);
    uint8_t buffer[256];
    int status = 0;
    if (s > 256) {
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }
    status |= mbedtls_mpi_write_binary (n, buffer, s);
    status |= hashData(mdCtx, buffer, s);
    return status;
}
