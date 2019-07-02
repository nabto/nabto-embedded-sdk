#ifndef NM_ACCESS_CONTROL_H
#define NM_ACCESS_CONTROL_H

#include <platform/np_access_control.h>

#include <stdbool.h>

//bool nm_access_control_can_access(uint8_t* fingerprint, enum np_access_control_permission feature);

#define NM_IAM_POLICY_NAME_LEN 32

// Max levels of nested conditions, such that we can use recursive functions instead of relying on tree traversals.
#define NM_IAM_MAX_NESTED_CONDITION_EXPRESSIONS 10

enum nm_iam_evaluation_result {
    NM_IAM_EVALUATION_RESULT_NONE,
    NM_IAM_EVALUATION_RESULT_ALLOW,
    NM_IAM_EVALUATION_RESULT_DENY
};

enum nm_iam_value_type {
    NM_IAM_VALUE_TYPE_NUMBER,
    NM_IAM_VALUE_TYPE_STRING
};

enum nm_iam_predicate_type {
    NM_IAM_PREDICATE_TYPE_STRING_EQUAL,
    NM_IAM_PREDICATE_TYPE_NUMBER_EQUAL,
};

enum nm_iam_boolean_expression_type {
    NM_IAM_BOOLEAN_EXPRESSION_TYPE_AND,
    NM_IAM_BOOLEAN_EXPRESSION_TYPE_OR,
};



enum nm_iam_effect {
    NM_IAM_EFFECT_ALLOW,
    NM_IAM_EFFECT_DENY
};

struct nm_iam_list_entry;
struct nm_iam_list_entry {
    struct nm_iam_list_entry* next;
    struct nm_iam_list_entry* prev;
    void* item;
};

struct nm_iam_list {
    struct nm_iam_list_entry sentinel;
};

struct nm_iam_variable {
    enum nm_iam_value_type type;
    const char* name;
};

// TODO rename to attribute value
struct nm_iam_value {
    enum nm_iam_value_type type;
    union {
        uint32_t number;
        const char* string;
    } data;
};

struct nm_iam_variable_instance {
    struct nm_iam_variable* variable;
    struct nm_iam_value value;
};

enum nm_iam_expression_type {
    NM_IAM_EXPRESSION_TYPE_PREDICATE,
    NM_IAM_EXPRESSION_TYPE_BOOLEAN_EXPRESSION
};

enum nm_iam_predicate_item_type {
    NM_IAM_PREDICATE_ITEM_TYPE_VARIABLE,
    NM_IAM_PREDICATE_ITEM_TYPE_VALUE
};

struct nm_iam_predicate_item {
    enum nm_iam_predicate_item_type type;
    union {
        struct nm_iam_variable* variable;
        struct nm_iam_value value;
    } data;
};

struct nm_iam_predicate {
    enum nm_iam_predicate_type type;
    struct nm_iam_variable* lhs;
    struct nm_iam_predicate_item rhs;
};

struct nm_iam_boolean_expression {
    enum nm_iam_boolean_expression_type type;
    struct nm_iam_expression* lhs;
    struct nm_iam_expression* rhs;
};

struct nm_iam_expression {
    enum nm_iam_expression_type type;
    union {
        struct nm_iam_predicate predicate;
        struct nm_iam_boolean_expression booleanExpression;
    } data;
};

struct nm_iam_statement {
    struct nm_iam_list actions;
    enum nm_iam_effect effect;
    struct nm_iam_expression* conditions;
};

struct nm_iam_policy {
    char name[NM_IAM_POLICY_NAME_LEN];
    struct nm_iam_list statements;
};

struct nm_iam_role {
    const char* name;
    struct nm_iam_list policies;
};


struct nm_iam_user {
    const char* name;
    struct nm_iam_list* roles;
};

struct nm_iam_action {
    // the pointer is just a pointer to the name.
};

struct nm_iam {
    struct nm_iam_list users;
    struct nm_iam_list actions;
    struct nm_iam_list roles;
    struct nm_iam_list policies;
    struct nm_iam_list variables;
};

void nm_iam_init(struct nm_iam* iam);

void nm_iam_add_policy(struct nm_iam* iam, struct nm_iam_policy* policy);

enum nm_iam_evaluation_result nm_iam_eval_statement(struct nm_iam_statement* statement, struct nm_iam_user* user, struct nm_iam_list* variableInstances, struct nm_iam_action* action);

// test if a user has access to the given action by evaluating the roles the user is giving in the context given by the variable instances.
bool nn_iam_has_access_to_action(struct nm_iam* iam, struct nm_iam_user* user, struct nm_iam_list* variableInstances, struct nm_iam_action* action);

// VARIABLES
// return false if the variable could not be added to the list of known variables
bool nm_iam_add_variable(struct nm_iam* iam, const char* name, enum nm_iam_value_type type);

// return a variable or NULL if it does not exists.
struct nm_iam_variable* nm_iam_get_variable(struct nm_iam* iam, const char* name);

void nm_iam_init_variable_instance_integer(struct nm_iam_variable_instance* instance, struct nm_iam_variable* variable, uint32_t integer);
void nm_iam_init_variable_instance_string(struct nm_iam_variable_instance* instance, struct nm_iam_variable* variable, const char* string);


// ACTIONS
struct nm_iam_action* nm_iam_action_new(const char* name);
void nm_iam_action_free(struct nm_iam_action* action);

// operations on the iam object
bool nm_iam_add_action(struct nm_iam* iam, struct nm_iam_action* action);
struct nm_iam_action* nm_iam_get_action(struct nm_iam* iam, const char* name);

// Policies

struct nm_iam_policy* nm_iam_policy_new(struct nm_iam* iam, const char* name);
bool nm_iam_policy_free(struct nm_iam* iam, struct nm_iam_policy* policy);
void nm_iam_policy_add_statement(struct nm_iam_policy* policy, struct nm_iam_statement* statement);

// Test if action is allowed given the context.
typedef void(*nm_iam_is_action_allowed_cb)(bool status, void* userData);
bool nm_iam_async_is_action_allowed(struct nm_iam_list* roles, struct nm_iam_action* action, struct nm_iam_list* variables, nm_iam_is_action_allowed_cb cb, void* userData);

// LISTS
void nm_iam_list_init(struct nm_iam_list* list);
void nm_iam_list_clear(struct nm_iam_list* list);
void nm_iam_list_insert_entry_back(struct nm_iam_list* list, void* item);
void nm_iam_list_remove_entry(struct nm_iam_list_entry* entry);
struct nm_iam_list_entry* nm_iam_list_entry_new();
void nm_iam_list_entry_free(struct nm_iam_list_entry* entry);

// STATEMENTS
struct nm_iam_statement* nm_iam_statement_new();
void nm_iam_statement_free(struct nm_iam_statement* statement);
bool nm_iam_statement_has_action(struct nm_iam_statement* statement, struct nm_iam_action* action);
void nm_iam_statement_add_action(struct nm_iam_statement* statement, struct nm_iam_action* action);

// CONDITION EXPRESSIONS

struct nm_iam_expression* nm_iam_expression_new();
void nm_iam_expression_free(struct nm_iam_expression* expression);

struct nm_iam_expression* nm_iam_expression_and(struct nm_iam_expression* lhs, struct nm_iam_expression* rhs);

struct nm_iam_expression* nm_iam_expression_string_equal(struct nm_iam_variable* lhs, struct nm_iam_predicate_item rhs);
struct nm_iam_expression* nm_iam_expression_number_equal(struct nm_iam_variable* lhs, struct nm_iam_predicate_item rhs);

struct nm_iam_predicate_item nm_iam_predicate_item_string(const char* string);
struct nm_iam_predicate_item nm_iam_predicate_item_number(uint32_t number);
struct nm_iam_predicate_item nm_iam_predicate_item_variable(struct nm_iam_variable* variable);

#endif
