bool init_default_policies(const char* policiesFile)
{
    struct nm_policy_builder passwordPairingPolicy;
    nm_policy_builder_init(&passwordPairingPolicy, "PasswordPairing");

    struct nm_statement_builder allowPairing;
    nm_statement_builder_init(&allowPairing, NM_EFFECT_ALLOW);

    nm_statement_builder_add_action();


    struct nm_policy* passwordPairingPolicy = nm_policy_new("PasswordPairing");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(allowPairing, "Pairing:Get");
        nm_statement_add_action(allowPairing, "Pairing:Password");
        nm_policy_add_statement(passwordPairingPolicy, allowPairing);
    }

    struct nm_policy* tunnelAllPolicy = nm_policy_new("TunnelAll");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "TcpTunnel:GetService");
        nm_statement_add_action(stmt, "TcpTunnel:Connect");
        nm_statement_add_action(stmt, "TcpTunnel:ListServices");
        nm_policy_add_statement(tunnelAllPolicy, stmt);
    }

    struct nm_policy* pairedPolicy = nm_policy_new("Paired");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "Pairing:Get");
        nm_policy_add_statement(pairedPolicy, stmt);
    }
}
