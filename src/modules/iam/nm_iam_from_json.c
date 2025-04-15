#include "nm_iam_from_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"

#include "nm_iam_allocator.h"

#include <string.h>

struct nm_iam_role* nm_iam_role_from_json(const cJSON* json)
{
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* policies = cJSON_GetObjectItem(json, "Policies");

    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(policies))
    {
        return NULL;
    }

    struct nm_iam_role* role = nm_iam_role_new(id->valuestring);
    if (role == NULL) {
        return role;
    }
    size_t policiesSize = cJSON_GetArraySize(policies);
    for (size_t i = 0; i < policiesSize; i++) {
        cJSON* p = cJSON_GetArrayItem(policies, (int)i);
        // todo handle non strings.
        if (cJSON_IsString(p)) {
            nn_string_set_insert(&role->policies, p->valuestring);
        }
    }
    return role;
}

struct nm_iam_user* nm_iam_user_from_json(const cJSON* json, int version)
{
    cJSON* username = cJSON_GetObjectItem(json, "Username");
    cJSON* displayName = cJSON_GetObjectItem(json, "DisplayName");
    cJSON* sct = cJSON_GetObjectItem(json, "ServerConnectToken");
    cJSON* password = cJSON_GetObjectItem(json, "Password");
    cJSON* role = cJSON_GetObjectItem(json, "Role");
    cJSON* fcm = cJSON_GetObjectItem(json, "Fcm");
    cJSON* notificationCategories = cJSON_GetObjectItem(json, "NotificationCategories");
    cJSON* oauthSubject = cJSON_GetObjectItem(json, "OauthSubject");
    cJSON* fcmToken = NULL;
    cJSON* fcmProjectId = NULL;

    if (cJSON_IsObject(fcm)) {
        fcmToken = cJSON_GetObjectItem(fcm, "Token");
        fcmProjectId = cJSON_GetObjectItem(fcm, "ProjectId");
    }


    if (!cJSON_IsString(username)) {
        return NULL;
    }

    struct nm_iam_user* user = nm_iam_user_new(username->valuestring);
    if (user == NULL) {
        return NULL;
    }

    if (cJSON_IsString(displayName)) {
        nm_iam_user_set_display_name(user, displayName->valuestring);
    }

    if (version == 1) {
        cJSON* fingerprint = cJSON_GetObjectItem(json, "Fingerprint");
        if (cJSON_IsString(fingerprint)) {
           nm_iam_user_set_fingerprint(user, fingerprint->valuestring);
        }
    } else if (version == 2) {
        cJSON* fingerprints = cJSON_GetObjectItem(json, "Fingerprints");
        if (cJSON_IsArray(fingerprints)) {
            size_t fpsSize = cJSON_GetArraySize(fingerprints);
            for (size_t i = 0; i < fpsSize; i++) {
                cJSON* item = cJSON_GetArrayItem(fingerprints, (int)i);
                cJSON* fp = cJSON_GetObjectItem(item, "Fingerprint");
                cJSON* fpName = cJSON_GetObjectItem(item, "Name");
                char* fpNameStr = NULL;
                if (cJSON_IsString(fpName)) {
                    fpNameStr = fpName->valuestring;
                }

                if (cJSON_IsString(fp)) {
                    char* fpStr = fp->valuestring;
                    nm_iam_user_add_fingerprint(user, fpStr, fpNameStr);
                }
            }
        }
    }

    if (cJSON_IsString(password)) {
        nm_iam_user_set_password(user, password->valuestring);
    }

    if (cJSON_IsString(sct)) {
        nm_iam_user_set_sct(user, sct->valuestring);
    }

    if (cJSON_IsString(role)) {
        nm_iam_user_set_role(user, role->valuestring);
    }

    if (cJSON_IsString(fcmToken)) {
        // NOLINTNEXTLINE(clang-analyzer-core.NullDereference)
        nm_iam_user_set_fcm_token(user, fcmToken->valuestring);
    }

    if (cJSON_IsString(fcmProjectId)) {
        // NOLINTNEXTLINE(clang-analyzer-core.NullDereference)
        nm_iam_user_set_fcm_project_id(user, fcmProjectId->valuestring);
    }

    if (cJSON_IsArray(notificationCategories)) {
        cJSON* element = NULL;
        struct nn_string_set cs;
        nn_string_set_init(&cs, nm_iam_allocator_get());
        cJSON_ArrayForEach(element, notificationCategories) {
            if (cJSON_IsString(element)) {
                nn_string_set_insert(&cs, element->valuestring);
            }
        }
        nm_iam_user_set_notification_categories(user, &cs);
        nn_string_set_deinit(&cs);
    }

    if (cJSON_IsString(oauthSubject)) {
        nm_iam_user_set_oauth_subject(user, oauthSubject->valuestring);
    }

    return user;
}
