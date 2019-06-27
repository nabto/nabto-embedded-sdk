#ifndef NM_ACCESS_CONTROL_H
#define NM_ACCESS_CONTROL_H

#include <platform/np_access_control.h>

#include <stdbool.h>

//bool nm_access_control_can_access(uint8_t* fingerprint, enum np_access_control_permission feature);

#define NM_IAM_POLICY_NAME_LEN 32

enum nm_iam_variable_type {
    NM_IAM_VARIABLE_TYPE_INTEGER,
    NM_IAM_VARIABLE_TYPE_STRING
};

enum nm_iam_condition_type {
    NM_IAM_CONDITION_TYPE_STRING_EQUAL,
    NM_IAM_CONDITION_TYPE_STRING_VARIABLE_EQUAL,
    NM_IAM_CONDITION_TYPE_INTEGER_EQUAL,
    NM_IAM_CONDITION_TYPE_INTEGER_VARIABLE_EQUAL
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
    enum nm_iam_variable_type type;
    const char* name;
};

struct nm_iam_variable_instance {
    struct nm_iam_variable* variable;
    union data {
        uint32_t integer;
        const char* string;
    } data;
};



struct nm_iam_condition {
    enum nm_iam_condition_type type;
    union {
        struct {
            const char* variable;
            const char* string;
        } stringEqual;
        struct {
            const char* variable1;
            const char* variable2;
        } stringVariableEqual;
        struct {
            const char* variable;
            uint32_t integer;
        } integerEqual ;
        struct {
            const char* variable1;
            const char* variable2;
        } integerVariableEqual;
    } condition;
};

struct nm_iam_statement {
    struct nm_iam_list actions;
    enum nm_iam_effect effect;
    struct nm_iam_list conditions;
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


struct nm_iam {
    struct nm_iam_list users;
    struct nm_iam_list roles;
    struct nm_iam_list policies;
    struct nm_iam_list variables;
};

void nm_iam_init(struct nm_iam* iam);

// VARIABLES
// return false if the variable could not be added to the list of known variables
bool nm_iam_add_variable(struct nm_iam* iam, const char* name, enum nm_iam_condition_type type);

// return a variable or NULL if it does not exists.
struct nm_iam_variable* nm_iam_get_variable(struct nm_iam* iam, const char* name);

void nm_iam_init_variable_instance_integer(struct nm_iam_variable_instance* instance, struct nm_iam_variable* variable, uint32_t integer);
void nm_iam_init_variable_instance_string(struct nm_iam_variable_instance* instance, struct nm_iam_variable* variable, const char* string);


// ACTIONS
bool nm_iam_add_action(struct nm_iam* iam, const char* name);
struct nm_iam_action* nm_iam_get_action(struct nm_iam* iam, const char* name);


// Policies

struct nm_iam_policy* nm_iam_policy_new(struct nm_iam* iam, const char* name);
bool nm_iam_policy_free(struct nm_iam* iam, struct nm_iam_policy* policy);

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

// CONDITIONS
struct nm_iam_condition* nm_iam_condition_new();
void nm_iam_condition_free(struct nm_iam_condition* condition);

#endif
