#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam_user.h>
#include <modules/iam/nm_iam_serializer.h>
#include <nn/llist.h>
#include <nn/string_set.h>
#include <nlohmann/json.hpp>

namespace nabto {
namespace test {

struct nm_iam_state* state;

void initState()
{
    struct nn_string_set cats;
    struct nm_iam_user usr;
    state = nm_iam_state_new();
    state->passwordOpenPassword = strdup("password");
}

std::string s1 = R"(
{
  "OpenPairingPassword":"password",
  "OpenPairingSct":"token",
  "Users": [
    {
      "DisplayName":"Display Name",
      "Fingerprint":"fingerprint",
      "Role":"role1",
      "ServerConnectToken":"token2",
      "Password":"password2",
      "Username":"username",
      "Fcm": {
        "Token":"fcm_token",
        "ProjectId":"fcm_project"
      },
      "NotificationCategories": ["cat1","cat2"]
    }
  ],
  "Version":1
}
)";

} } // namespaces

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(load_dump_state, *boost::unit_test::timeout(180))
{
    NabtoDevice* d = nabto_device_new();
    struct nm_iam iam;
    nm_iam_init(&iam, d, NULL);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_SUITE_END();
