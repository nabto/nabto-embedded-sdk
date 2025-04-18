#include "nm_iam_to_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"

#include <cjson/cJSON.h>

cJSON* nm_iam_role_to_json(struct nm_iam_role* role)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Id", cJSON_CreateString(role->id));

    cJSON* policies = cJSON_CreateArray();
    const char* str = NULL;
    NN_STRING_SET_FOREACH(str, &role->policies) {
        cJSON_AddItemToArray(policies, cJSON_CreateString(str));
    }

    cJSON_AddItemToObject(root, "Policies", policies);
    return root;
}


cJSON* nm_iam_user_to_json(struct nm_iam_user* user)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "Username", cJSON_CreateString(user->username));

    cJSON* fingerprints = cJSON_AddArrayToObject(root, "Fingerprints");
    struct nm_iam_user_fingerprint* fp = NULL;
    NN_LLIST_FOREACH(fp, &user->fingerprints) {
        cJSON* fpObj = cJSON_CreateObject();
        if (fp->fingerprint != NULL) {
            cJSON_AddItemToObject(fpObj, "Fingerprint", cJSON_CreateString(fp->fingerprint));
        }
        if (fp->name != NULL) {
            cJSON_AddItemToObject(fpObj, "Name", cJSON_CreateString(fp->name));
        }
        cJSON_AddItemToArray(fingerprints, fpObj);
    }

    if (user->displayName != NULL) {
        cJSON_AddItemToObject(root, "DisplayName", cJSON_CreateString(user->displayName));
    }
    if (user->sct != NULL) {
        cJSON_AddItemToObject(root, "ServerConnectToken", cJSON_CreateString(user->sct));
    }
    if (user->password != NULL) {
        cJSON_AddItemToObject(root, "Password", cJSON_CreateString(user->password));
    }

    if (user->role != NULL) {
        cJSON_AddItemToObject(root, "Role", cJSON_CreateString(user->role));
    }

    if (user->fcmToken != NULL || user->fcmProjectId != NULL) {
        cJSON* fcm = cJSON_CreateObject();
        if (user->fcmToken != NULL) {
            cJSON_AddItemToObject(fcm, "Token", cJSON_CreateString(user->fcmToken));
        }
        if (user->fcmProjectId != NULL) {
            cJSON_AddItemToObject(fcm, "ProjectId", cJSON_CreateString(user->fcmProjectId));
        }
        cJSON_AddItemToObject(root, "Fcm", fcm);
    }

    if (!nn_string_set_empty(&user->notificationCategories)) {
        cJSON* notificationCategories = cJSON_CreateArray();
        const char* s = NULL;
        NN_STRING_SET_FOREACH(s, &user->notificationCategories) {
            cJSON_AddItemToArray(notificationCategories, cJSON_CreateString(s));
        }
        cJSON_AddItemToObject(root, "NotificationCategories", notificationCategories);
    }

    if (user->oauthSubject != NULL) {
        cJSON_AddItemToObject(root, "OauthSubject", cJSON_CreateString(user->oauthSubject));
    }


    return root;
}
