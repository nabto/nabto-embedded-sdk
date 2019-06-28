#include "nm_access_control_tests.h"
#include "nm_access_control.h"

void nm_iam_test_prepare_firmware_iam(struct nm_iam* iam)
{
    nm_iam_add_action(iam, nm_iam_action_new("firmware:Update"));
    nm_iam_add_action(iam, nm_iam_action_new("firmware:Get"));
}

void nm_iam_test_prepare_tunnel_iam(struct nm_iam* iam)
{
    nm_iam_add_action(iam, nm_iam_action_new("tunnel:Open"));
    nm_iam_add_action(iam, nm_iam_action_new("tunnel:Get"));
}

void nm_iam_test_add_firmware_update_policy(struct nm_iam* iam)
{
    struct nm_iam_policy* policy = nm_iam_policy_new(iam, "FirmwareUpdate");

    struct nm_iam_statement* statement = nm_iam_statement_new();
    nm_iam_statement_add_action(statement, nm_iam_get_action(iam, "firmware:Update"));
    nm_iam_statement_add_action(statement, nm_iam_get_action(iam, "firmware:Get"));

    nm_iam_policy_add_statement(policy, statement);
    nm_iam_add_policy(iam, policy);
}

void nm_iam_test_add_ssh_tunnel_policy(struct nm_iam* iam)
{
    struct nm_iam_policy* policy = nm_iam_policy_new(iam, "SshAccess");

    struct nm_iam_statement* statement = nm_iam_statement_new();
    nm_iam_statement_add_action(statement, nm_iam_get_action(iam, "tunnel:Open"));
    nm_iam_statement_add_action(statement, nm_iam_get_action(iam, "tunnel:Get"));

    // TODO add conditions for port and host
    //struct nm_iam_condition* hostMatches = nm_iam_condition_new();

//    nm_iam_statement_add_condition()

    nm_iam_policy_add_statement(policy, statement);
    nm_iam_add_policy(iam, policy);
}


void nm_iam_test_create_programmatic_policy()
{
    struct nm_iam iam;
    nm_iam_init(&iam);
    nm_iam_test_prepare_firmware_iam(&iam);
    nm_iam_test_prepare_tunnel_iam(&iam);
    nm_iam_test_add_firmware_update_policy(&iam);
    nm_iam_test_add_ssh_tunnel_policy(&iam);

}
