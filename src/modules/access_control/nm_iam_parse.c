#include "nm_iam_parse.h"

#include <cjson/cJSON.h>

/**
Example policy
{
  "version": 1,
  "name": "FirmwareUpdate",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "firmeware:update", "firmware:show" ]
    }
  ]
}
*/

/**
 * Example policy

{
  "version": 1,
  "name": "SshTunnels",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "tcptunnel:Open", "tcptunnel:Get" ],
      "condition": [
        { "StringEqual": { "tcptunnel:Host": [ "localhost" ] } },
        { "integerEqual": { "tcptunnel:Port": [ 22 ] } }
      ]
    },
    {
      "effect": "allow",
      "actions": [ "tcptunnel:List" ]
    }
  ]
}
 */


/**
 * Example policy

{
  "version": 1,
  "name": "ShowOwnTunnels",
  "statements": [
    {
      "effect": "allow",
      "actions": [ "tcptunnel:Show" ],
      "condition": {
        "StringEqual": [
          {"Attribute": "tcptunnel:UserId" },
          {"Attribute": "connection:UserId"}
        ] }
    }
  ]
}
 */

struct nm_iam_policy* nm_iam_parse_policy_json(struct nm_iam* iam, cJSON* root);
bool nm_iam_parse_statement(struct nm_iam* iam, cJSON* statement, struct nm_iam_policy* policy);
bool nm_iam_parse_statement_effect(cJSON* effect, struct nm_iam_statement* statement);
bool nm_iam_parse_statement_actions(struct nm_iam* iam, cJSON* actions, struct nm_iam_statement* statement);
struct nm_iam_expression* nm_iam_parse_expression(struct nm_iam* iam, cJSON* conditions);
struct nm_iam_expression* nm_iam_parse_boolean_expression(struct nm_iam* iam, cJSON* list, enum nm_iam_boolean_expression_type type);
struct nm_iam_expression* nm_iam_parse_predicate(struct nm_iam* iam, cJSON* predicate, enum nm_iam_predicate_type type);
bool nm_iam_parse_predicate_item(struct nm_iam* iam, cJSON* obj, struct nm_iam_predicate_item* item);

struct nm_iam_policy* nm_iam_parse_policy(struct nm_iam* iam, const char* json)
{
    cJSON* root = cJSON_Parse(json);
    struct nm_iam_policy* policy = NULL;
    if (root == NULL) {
        return NULL;
    }

    policy = nm_iam_parse_policy_json(iam, root);

    cJSON_Delete(root);
    return policy;
}

struct nm_iam_policy* nm_iam_parse_policy_json(struct nm_iam* iam, cJSON* root)
{
    const cJSON* version = NULL;
    const cJSON* name = NULL;
    const cJSON* statements = NULL;
    cJSON* statement = NULL;
    version = cJSON_GetObjectItemCaseSensitive(root, "version");
    name = cJSON_GetObjectItemCaseSensitive(root, "name");
    statements = cJSON_GetObjectItemCaseSensitive(root, "statements");
    if (!cJSON_IsNumber(version) ||
        !cJSON_IsString(name) ||
        !cJSON_IsArray(statements))
    {
        return NULL;
    }

    if (version->valueint != 1) {
        // invalid version
        return NULL;
    }

    struct nm_iam_policy* policy = nm_iam_policy_new(iam, name->valuestring);

    cJSON_ArrayForEach(statement, statements)
    {
        if (!nm_iam_parse_statement(iam, statement, policy)) {
            // TODO
        }
    }
    return policy;
}

bool nm_iam_parse_statement(struct nm_iam* iam, cJSON* statement, struct nm_iam_policy* policy)
{
    cJSON* effect =  cJSON_GetObjectItemCaseSensitive(statement, "effect");
    cJSON* actions = cJSON_GetObjectItemCaseSensitive(statement, "actions");
    cJSON* conditions = cJSON_GetObjectItemCaseSensitive(statement, "conditions");

    if (!cJSON_IsString(effect) ||
        !cJSON_IsArray(actions))
    {
        return false;
    }
    if ((strcmp(effect->valuestring, "Allow") != 0 ) &&
        (strcmp(effect->valuestring, "Deny") != 0))
    {
        return false;
    }

    if (conditions && !cJSON_IsArray(conditions)) {
        return false;
    }

    struct nm_iam_statement* iamStatement = nm_iam_statement_new();
    if (iamStatement == NULL) {
        return false;
    }
    nm_iam_list_insert_entry_back(&policy->statements, iamStatement);

    if (nm_iam_parse_statement_effect(effect, iamStatement) &&
        nm_iam_parse_statement_actions(iam, actions, iamStatement))
    {
        struct nm_iam_expression* expression = nm_iam_parse_expression(iam, conditions);
        iamStatement->conditions = expression;
        return true;
    }
    return false;
}

bool nm_iam_parse_statement_effect(cJSON* effect, struct nm_iam_statement* statement)
{
    if (strcmp(effect->valuestring, "Allow") == 0) {
        statement->effect = NM_IAM_EFFECT_ALLOW;
    } else if (strcmp(effect->valuestring, "Deny") == 0) {
        statement->effect = NM_IAM_EFFECT_DENY;
    } else {
        return false;
    }

    return true;
}

bool nm_iam_parse_statement_actions(struct nm_iam* iam, cJSON* actions, struct nm_iam_statement* statement)
{
    cJSON* action;
    cJSON_ArrayForEach(action, actions) {
        if (!cJSON_IsString(action)) {
            return false;
        }
        struct nm_iam_action* iamAction = nm_iam_get_action(iam, action->valuestring);
        if (!iamAction) {
            return false;
        }
        nm_iam_list_insert_entry_back(&statement->actions, iamAction);
    }
    return true;
}

struct nm_iam_expression* nm_iam_parse_expression(struct nm_iam* iam, cJSON* conditions)
{
    if (conditions == NULL) {
        return NULL;
    }
    cJSON* and =  cJSON_GetObjectItemCaseSensitive(conditions, "And");
    cJSON* or = cJSON_GetObjectItemCaseSensitive(conditions, "Or");
    cJSON* stringEqual = cJSON_GetObjectItemCaseSensitive(conditions, "StringEqual");
    cJSON* numberEqual = cJSON_GetObjectItemCaseSensitive(conditions, "NumberEqual");

    if (and) {
        return nm_iam_parse_boolean_expression(iam, and, NM_IAM_BOOLEAN_EXPRESSION_TYPE_AND);
    } else if (or) {
        return nm_iam_parse_boolean_expression(iam, or, NM_IAM_BOOLEAN_EXPRESSION_TYPE_OR);
    } else if (stringEqual) {
        return nm_iam_parse_predicate(iam, stringEqual, NM_IAM_PREDICATE_TYPE_STRING_EQUAL);
    } else if (numberEqual) {
        return nm_iam_parse_predicate(iam, numberEqual, NM_IAM_PREDICATE_TYPE_NUMBER_EQUAL);
    }

    /* // TODO */
    return NULL;
}

struct nm_iam_expression* nm_iam_parse_boolean_expression(struct nm_iam* iam, cJSON* list, enum nm_iam_boolean_expression_type type)
{
    struct nm_iam_expression* expression = nm_iam_boolean_expression_new(type);

    cJSON* j;

    cJSON_ArrayForEach(j, list)
    {
        struct nm_iam_expression* e = nm_iam_parse_expression(iam, j);
        nm_iam_list_insert_entry_back(&expression->data.booleanExpression.expressions, e);
    }
    return expression;
}

struct nm_iam_expression* nm_iam_parse_predicate(struct nm_iam* iam, cJSON* predicate, enum nm_iam_predicate_type type)
{
    int arraySize = cJSON_GetArraySize(predicate);
    if (arraySize != 2) {
        return NULL;
    }
    struct nm_iam_expression* expression = nm_iam_predicate_new(type);

    nm_iam_parse_predicate_item(iam, cJSON_GetArrayItem(predicate, 0), &expression->data.predicate.lhs);
    nm_iam_parse_predicate_item(iam, cJSON_GetArrayItem(predicate, 1), &expression->data.predicate.rhs);

    return false;

}

bool nm_iam_parse_predicate_item(struct nm_iam* iam, cJSON* obj, struct nm_iam_predicate_item* item)
{
    cJSON* attribute = cJSON_GetObjectItemCaseSensitive(obj, "Attribute");
    if (cJSON_IsNumber(obj)) {
        item->type = NM_IAM_PREDICATE_ITEM_TYPE_VALUE;
        item->data.value.type = NM_IAM_VALUE_TYPE_NUMBER;
        item->data.value.data.number = obj->valueint;
    } else if (cJSON_IsString(obj)) {
        item->type = NM_IAM_PREDICATE_ITEM_TYPE_VALUE;
        item->data.value.type = NM_IAM_VALUE_TYPE_STRING;
        item->data.value.data.string = strdup(obj->string);
    } else if (cJSON_IsObject(obj) && cJSON_IsString(attribute)) {
        item->type = NM_IAM_PREDICATE_ITEM_TYPE_ATTRIBUTE;
        struct nm_iam_attribute_name* attributeName = nm_iam_get_attribute_name(iam, attribute->string);
        item->data.attributeName = attributeName;
    } else {
        return false;
    }

    return true;
}

//bool nm_iam_parse_boolean_expression()
