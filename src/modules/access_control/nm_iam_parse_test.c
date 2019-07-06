
#include "nm_access_control.h"
#include "nm_iam_parse.h"
#include <platform/np_unit_test.h>

const char* testPolicy1 = "{ \"version\": 1, \"name\": \"FirmwareUpdate\", \"statements\": [ { \"effect\": \"Allow\", \"actions\": [ \"firmware:Update\", \"firmware:Show\" ] } ] }";

#include "test_data/policy_ssh_access.json.c"
#include "test_data/iam.json.c"


void test_parse_policy()
{
    struct nm_iam iam;
    nm_iam_init(&iam);

    struct nm_iam_policy* policy = nm_iam_parse_policy(&iam, testPolicy1);
    NABTO_TEST_CHECK(policy != NULL);
    NABTO_TEST_CHECK(strcmp(policy->name, "FirmwareUpdate") == 0);

    struct nm_iam_list_entry* iterator = policy->statements.sentinel.next;
    NABTO_TEST_CHECK(iterator != &policy->statements.sentinel);
    struct nm_iam_statement* statement = (struct nm_iam_statement*)iterator->item;
    NABTO_TEST_CHECK(statement->effect == NM_IAM_EFFECT_ALLOW);

    struct nm_iam_action* update = nm_iam_get_action(&iam, "firmware:Update");
    struct nm_iam_action* show = nm_iam_get_action(&iam, "firmware:Show");
    NABTO_TEST_CHECK(update != NULL);
    NABTO_TEST_CHECK(show != NULL);
    NABTO_TEST_CHECK(nm_iam_statement_has_action(statement, update));
    NABTO_TEST_CHECK(nm_iam_statement_has_action(statement, show));
}

void test_parse_policy2()
{
    struct nm_iam iam;
    nm_iam_init(&iam);

    struct nm_iam_policy* policy = nm_iam_parse_policy(&iam, policy_ssh_access_json);
    NABTO_TEST_CHECK(policy != NULL);
}

void test_parse_role()
{
    struct nm_iam iam;
    nm_iam_init(&iam);

    //nm_iam_parse_config(&iam, iam_json);
}

void nm_iam_parse_test()
{
    test_parse_policy();
    test_parse_policy2();
}
