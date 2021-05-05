#include <boost/test/unit_test.hpp>

#include <coap/nabto_coap_client.h>
#include <coap/nabto_coap_client_test.h>
#include <core/nc_coap_rest_error.h>

#include <nlohmann/json.hpp>

BOOST_AUTO_TEST_SUITE(nc_coap_rest_error_test)

BOOST_AUTO_TEST_CASE(no_content_type_no_message)
{
    struct nabto_coap_client_response* response = nabto_coap_client_test_create_response();

    struct nc_coap_rest_error error;

    BOOST_TEST(nc_coap_rest_error_decode_response(response, &error) == true);
    nc_coap_rest_error_deinit(&error);
//    nabto_coap_client_test_response_free(response);
}

BOOST_AUTO_TEST_CASE(no_content_type_with_message)
{
    struct nabto_coap_client_response* response = nabto_coap_client_test_create_response();

    const char* message = "foo";

    nabto_coap_client_test_response_set_payload(response, (const uint8_t*)message, strlen(message));

    struct nc_coap_rest_error error;

    BOOST_TEST(nc_coap_rest_error_decode_response(response, &error) == true);

    BOOST_TEST(std::string(error.message) == std::string(message));
    nc_coap_rest_error_deinit(&error);
//    nabto_coap_client_test_response_free(response);
}

BOOST_AUTO_TEST_CASE(cbor_error_code_and_message)
{
    std::string m = "foo";
    int c = 1;
    nlohmann::json e;
    e["Error"]["Code"] = c;
    e["Error"]["Message"] = m;
    std::vector<uint8_t> payload = nlohmann::json::to_cbor(e);
    struct nabto_coap_client_response* response = nabto_coap_client_test_create_response();

    struct nc_coap_rest_error error;

    nabto_coap_client_test_response_set_payload(response, payload.data(), payload.size());
    nabto_coap_client_test_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_client_test_response_set_code(response, NABTO_COAP_CODE_NOT_FOUND);
    BOOST_TEST(nc_coap_rest_error_decode_response(response, &error) == true);
    BOOST_TEST(std::string(error.message) == std::string(m));
    BOOST_TEST(error.nabtoErrorCode == c);

    nc_coap_rest_error_deinit(&error);
//    nabto_coap_client_test_response_free(response);
}


BOOST_AUTO_TEST_SUITE_END()
