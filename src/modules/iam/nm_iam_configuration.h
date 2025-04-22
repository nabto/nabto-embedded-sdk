#ifndef NM_IAM_CONFIGURATION_H_
#define NM_IAM_CONFIGURATION_H_

#include <nn/llist.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

/*************************
 * Structure Definitions *
 *************************/

/**
 * Enum defining the effect of statements. The enum is also used to
 * define the result of an evaluated statement. This is the purpose of
 * the NO_MATCH and ERROR values. Only ALLOW and DENY should be used
 * as configuration for a statement.
 *
 * `ALLOW`: Actions in this statement should be allowed
 *  JSON representation: `{ "Effect": "Allow" }`
 *
 * `DENY`: Actions in this statement should be denied
 * JSON representation: `{ "Effect": "Deny" }`
 *
 * `NO_MATCH`: Internal only: used to indicate the action was not covered by the statement
 * JSON representation: N/A, not used for configuration
 *
 * `ERROR`    Internal only: an error occured during evaluation
 * JSON representation: N/A, not used for configuration
 */
enum nm_iam_effect {
    NM_IAM_EFFECT_ALLOW,
    NM_IAM_EFFECT_DENY,
    NM_IAM_EFFECT_NO_MATCH,
    NM_IAM_EFFECT_ERROR
};

/**
 * Enum defining how to match a condition. When matching, a list of
 * attributes are provided which is matched with the values configured
 * in the condition.
 *
 * A condition is considered a match if an attribute with the same key as the condition key is
 * provided and its value matches any value of the condition. That is eg. if using STRING_EQUALS,
 * the attribute matching the condition key must be equal to one of the condition values. Whereas
 * with STRING_NOT_EQUALS, the attribute value must not be equal to any of the condition values.
 *
 * To simplify the internal structure all values are stored as strings.
 *
 * JSON representations:
 * @param STRING_EQUALS               `{"StringEquals": {"<key>": [ "value1", ...]}}`
 * @param STRING_NOT_EQUALS           `{"StringNotEquals": {"<key>": [ "value1", ...]}}`
 * @param NUMERIC_EQUALS              `{"NumericEquals": {"<key>": [ "42.3"]}}`
 * @param NUMERIC_NOT_EQUALS          `{"NumericNotEquals": {"<key>": [ "42.3"]}}`
 * @param NUMERIC_LESS_THAN           `{"NumericLessThan": {"<key>": [ "42.3"]}}`
 * @param NUMERIC_LESS_THAN_EQUALS    `{"NumericLessThanEquals": {"<key>": [ "42.3"]}}`
 * @param NUMERIC_GREATER_THAN        `{"NumericGreaterThan": {"<key>": [ "42.3"]}}`
 * @param NUMERIC_GREATER_THAN_EQUALS `{"NumericGreaterThanEquals": {"<key>": [ "42.3"]}}`
 * @param BOOL                        `{"Bool": {"<key>": [ "true" || "false"]}}`
 */
enum nm_iam_condition_operator {
    NM_IAM_CONDITION_OPERATOR_STRING_EQUALS,
    NM_IAM_CONDITION_OPERATOR_STRING_NOT_EQUALS,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_EQUALS,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_NOT_EQUALS,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_LESS_THAN_EQUALS,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN,
    NM_IAM_CONDITION_OPERATOR_NUMERIC_GREATER_THAN_EQUALS,
    NM_IAM_CONDITION_OPERATOR_BOOL
};


struct nm_iam_condition {
    enum nm_iam_condition_operator op; // match operator
    char* key; // attribute key to match values
    struct nn_string_set values; // set of acceptable values
    struct nn_llist_node listNode;
};

struct nm_iam_statement {
    enum nm_iam_effect effect;
    struct nn_string_set actions; // set of action strings
    struct nn_llist conditions; // Linked list of struct nm_iam_condition
    struct nn_llist_node listNode;
};

struct nm_iam_policy {
    char* id; // Policy ID
    struct nn_llist statements; // Linked list of struct nm_iam_statement
    struct nn_llist_node listNode;
};

struct nm_iam_role {
    char* id; // Role ID
    struct nn_string_set policies; // set of policy IDs
    struct nn_llist_node listNode;
};

struct nm_iam_configuration {
    struct nn_llist roles; // linked list of struct nm_iam_role
    struct nn_llist policies; // linked list of struct nm_iam_policy

    char* unpairedRole;
};

/*************************
 * Configuration Builder *
 *************************/

/**
 * @intro Configuration Builder
 *
 * Build a new IAM configuration consisting of policies and roles.
 *
 * Header: `src/modules/iam/nm_iam_configuration.h`
 */

/**
 * Create IAM configuration
 *
 * @return NULL iff the configuration could not be created
 */
struct nm_iam_configuration* nm_iam_configuration_new();

/**
 * Free IAM configuration if the ownership was not transfered to an
 * IAM module with nm_iam_load_configuration()
 *
 * @param conf [in]  Configuration to free
 */
void nm_iam_configuration_free(struct nm_iam_configuration* conf);

/**
 * Set the role for unpaired connections on the system to allow
 * unknown users to connect and do pairing (and perhaps retrieve some
 * public information).
 *
 * @param conf [in]  The IAM configuration,
 * @param role [in]  The role to set as the unpaired role. The string is copied into the module.
 * @return false iff the role was not set.
 */
bool nm_iam_configuration_set_unpaired_role(struct nm_iam_configuration* conf, const char* role);

/**
 * Add a policy to the IAM configuration. The ownership of the policy
 * is transferred to the IAM configuration.
 *
 * @param conf [in]    The IAM configuration,
 * @param policy [in]  The policy to add to the configuration.
 * @return false iff the policy was not added.
 */
bool nm_iam_configuration_add_policy(struct nm_iam_configuration* conf, struct nm_iam_policy* policy);

/**
 * Add a role to the IAM configuration. The ownership of the role is
 * transferred to the IAM configuration.
 *
 * @param conf [in]  The IAM configuration,
 * @param role [in]  The role to add to the configuration.
 * @return false iff the role was not added.
 */
bool nm_iam_configuration_add_role(struct nm_iam_configuration* conf, struct nm_iam_role* role);


/******************
 * Policy Builder *
 ******************/

/**
 * Create a new policy with the specified name
 *
 * @param name [in]   Name of new policy
 * @return NULL iff the policy could not be created
 */
struct nm_iam_policy* nm_iam_configuration_policy_new(const char* name);

/**
 * Free policy created with nm_iam_configuration_policy_new() if the
 * ownership has not been transferred to an nm_iam_configuration.
 *
 * @param policy [in]   Policy to free
 */
void nm_iam_configuration_policy_free(struct nm_iam_policy* poilicy);

/**
 * Create a statement for a policy
 *
 * @param policy [in]   Policy to create statement in
 * @param effect [in]   Effect the statement should impose on its actions
 * @return statement reference to use when adding actions or conditions. Reference is valid for the lifetime of the policy
 *         NULL if statement could not be created
 */
struct nm_iam_statement* nm_iam_configuration_policy_create_statement(struct nm_iam_policy* policy, enum nm_iam_effect effect);

/**
 * Add action to a statement.
 *
 * @param statement [in]  Statement to add action to
 * @param action [in]     Action to add. String is copied into the statement.
 * @return false iff the action could not be added
 */
bool nm_iam_configuration_statement_add_action(struct nm_iam_statement* statement, const char* action);

/**
 * Create a condition for a statement
 *
 * @param statement [in]  Statement to create condition in
 * @param op [in]         Operator to use for value matching
 * @param key [in]        Attribute key to match values to. String is copied into condition.
 * @return condition reference to use when adding values. Reference is valid for the lifetime of the policy.
 *         NULL if the condition could not be created
 */
struct nm_iam_condition* nm_iam_configuration_statement_create_condition(struct nm_iam_statement* statement, enum nm_iam_condition_operator op, const char* key);

/**
 * Add a value to the condition which will make the condition evaluate
 * to true.
 *
 * @param condition [in]  Condition to add value to
 * @param value [in]      Value to be added. String is copied into the condition
 * @return false iff the value could not be added
 */
bool nm_iam_configuration_condition_add_value(struct nm_iam_condition* condition, const char* value);

/****************
 * Role Builder *
 ****************/
/**
 * Create a new role with the specified name.
 *
 * @param name [in]  Name of new role
 * @return NULL iff the role could not be created
 */
struct nm_iam_role* nm_iam_configuration_role_new(const char* name);

/**
 * Free a role.
 *
 * @param role [in]  Role to free
 */
void nm_iam_configuration_role_free(struct nm_iam_role* role);

/**
 * Add a policy reference to a role.
 *
 * @param role [in] The role to add policy to.
 * @param policy [in] is the name of an `nm_iam_policy`. The string is copied into the role.
 * @return false iff the policy could not be added
 */
bool nm_iam_configuration_role_add_policy(struct nm_iam_role* role, const char* policy);


#ifdef __cplusplus
} //extern "C"
#endif

#endif
