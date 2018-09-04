#include <nabto_types.h>
#include <platform/np_unit_test.h>
#include "nm_dtls_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct np_test_system nts;

const char devicePublicKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBaTCCARCgAwIBAgIJAOR5U6FNgvivMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMM\r\n"
"BW5hYnRvMB4XDTE4MDgwNzA2MzgyN1oXDTQ4MDczMDA2MzgyN1owEDEOMAwGA1UE\r\n"
"AwwFbmFidG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARjUmtqeqYTC+y/YYrk\r\n"
"66RU+FyN45b4xGIsKnLtd2l1x1zuF7adCCHT5pNVNi8dlZpytJNkVCNeWO1AF64l\r\n"
"H8ayo1MwUTAdBgNVHQ4EFgQUjq36vzjxAQ7I8bMejCf1/m0eQ2YwHwYDVR0jBBgw\r\n"
"FoAUjq36vzjxAQ7I8bMejCf1/m0eQ2YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\r\n"
"PQQDAgNHADBEAiBF98p5zJ+98XRwIyvCJ0vcHy/eJM77fYGcg3J/aW+lIgIgMMu4\r\n"
"XndF4oYF4h6yysELSJfuiamVURjo+KcM1ixwAWo=\r\n"
"-----END CERTIFICATE-----\r\n";
/**
 * extract fingerprint form shell
 *
 * openssl ec -in device.pem -pubout > devicepublickey.pem
 * openssl ec -pubin -in devicepublickey.pem -outform der > devicepublickey.der
 * sha256sum devicepublickey.der 
 * dd5fec4f27b5657cb75e5e247fe792cc096adc3670897660946278d67d9d95f7  devicepublickey.der
 *
 * short form: openssl ec -in device.pem -pubout -outform der | sha256sum
 * dd5fec4f27b5657cb75e5e247fe792cc096adc3670897660946278d67d9d95f7
 */


const char certFingerprint[] = { 0xdd, 0x5f, 0xec, 0x4f, 0x27, 0xb5, 0x65, 0x7c, 0xb7, 0x5e, 0x5e, 0x24, 0x7f, 0xe7, 0x92, 0xcc};


void on_check_fail(const char* file, int line)
{
    printf("check failed: %s:%i\n", file, line);
}

int main() {
    nts.on_check_fail = on_check_fail;
    uint8_t fp[16];
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    
    int status = mbedtls_x509_crt_parse(&chain, (const unsigned char*)devicePublicKey, strlen(devicePublicKey)+1);
    NABTO_TEST_CHECK(status == 0);

    np_error_code ec = nm_dtls_util_fp_from_crt(&chain, fp);
    
    NABTO_TEST_CHECK(ec == NABTO_EC_OK);

    NABTO_TEST_CHECK(memcmp(certFingerprint, fp, 16) == 0);
    
    printf("%i errors, %i ok checks\n", nts.fail, nts.ok);
    if (nts.fail > 0) {
        exit(1);
    } else {
        exit(0);
    }
}
