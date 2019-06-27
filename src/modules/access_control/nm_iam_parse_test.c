
const char* testPolicy1 = "{ \"version\": 1, \"name\": \"FirmwareUpdate\", \"statements\": [ { \"effect\": \"allow\", \"actions\": [ \"firmeware:update\", \"firmware:show\" ] } ] }";


bool test_parse_policy()
{
    struct nm_iam iam;
    nm_iam_init(&iam);
    if (!nm_iam_parse_policy(&iam, testPolicy1)) {
        return false;
    }



}
