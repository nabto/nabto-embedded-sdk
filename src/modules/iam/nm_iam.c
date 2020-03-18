#include "nm_iam.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"

#include <modules/policies/nm_effect.h>
#include <modules/policies/nm_policy.h>


static enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct np_string_map* attributes);
static enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct np_string_map* attributes);

void nm_iam_init(struct nm_iam* iam)
{
    np_vector_init(&iam->users, NULL);
    np_vector_init(&iam->roles, NULL);
    np_vector_init(&iam->policies, NULL);
}

void nm_iam_deinit(struct nm_iam* iam)
{
    np_vector_deinit(&iam->users);
    np_vector_deinit(&iam->roles);
    np_vector_deinit(&iam->policies);
}

bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct np_string_map* attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(iam->device, ref, &fingerprint);
    if (ec) {
        return false;
    }

    struct np_string_map attributes;
    np_string_map_init(&attributes);


    if (attributesIn) {
        struct np_string_map_item* item;
        NP_STRING_MAP_FOREACH(item, attributesIn) {
            np_string_map_insert(&attributes, item->key, item->value);
        }
    }

    struct nm_iam_user* user = nm_iam_find_user_by_fingerprint(iam, fingerprint);
    nabto_device_string_free(fingerprint);

    enum nm_effect effect;

    if (user) {
        np_string_map_insert(&attributes, "Connection:UserId", user->id);
        effect = nm_iam_check_access_user(iam, user, action, &attributes);
    } else {
        effect = nm_iam_check_access_role(iam, iam->unpairedRole, action, &attributes);
    }

    bool verdict = false;
    if (effect == NM_EFFECT_ALLOW) {
        verdict = true;
    }

    return verdict;
}


enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct np_string_map* attributes)
{
    // go through all the users roles and associated policies, If atlease one policy ends in a rejection reject the access. If there's no rejections but an accept, then return accepted.

    const char* roleStr;
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    NP_STRING_SET_FOREACH(roleStr, &user->roles)
    {
        struct nm_iam_role* role = nm_iam_find_role(iam, roleStr);

        enum nm_effect e = nm_iam_check_access_role(iam, role, action, attributes);

        if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY) {
            return e;
        }
        if (e == NM_EFFECT_ALLOW) {
            result = NM_EFFECT_ALLOW;
        }

    }
    return result;
}

enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct np_string_map* attributes)
{
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    const char* policyStr;
    NP_STRING_SET_FOREACH(policyStr, &role->policies)
    {
        struct nm_policy* policy = nm_iam_find_policy(iam, policyStr);

        enum nm_effect e = nm_policy_eval(policy, action, attributes);
        if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY) {
            return e;
        }
        if (e == NM_EFFECT_ALLOW) {
            result = NM_EFFECT_ALLOW;
        }
    }
    return result;
}
