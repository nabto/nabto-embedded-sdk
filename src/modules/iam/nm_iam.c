#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_role.h"
#include "nm_iam_user.h"
#include "policies/nm_policy.h"

#include <api/nabto_device_threads.h>
#include <nabto/nabto_device_experimental.h>

#include <nn/log.h>

#include "nm_iam_allocator.h"


#include <time.h>
static const char* LOGM = "iam";

void nm_iam_lock(struct nm_iam* iam) {
    nabto_device_threads_mutex_lock(iam->mutex);
}
void nm_iam_unlock(struct nm_iam* iam) {
    nabto_device_threads_mutex_unlock(iam->mutex);
}

bool nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger)
{
    memset(iam, 0, sizeof(struct nm_iam));
    iam->mutex = nabto_device_threads_create_mutex();
    if (iam->mutex == NULL) {
        return false;
    }
    srand((unsigned)time(0));
    iam->device = device;
    iam->logger = logger;

    iam->usernameMaxLength = 64;
    iam->displayNameMaxLength = 64;
    iam->passwordMinLength = 4;
    iam->passwordMaxLength = 64;
    iam->fcmTokenMaxLength = 1024;
    iam->fcmProjectIdMaxLength = 256;
    iam->oauthSubjectMaxLength = 64;
    iam->sctMaxLength = 64;
    iam->maxUsers = SIZE_MAX;
    iam->friendlyNameMaxLength = 64;

    iam->state = nm_iam_state_new();
    iam->conf = nm_iam_configuration_new();
    if (iam->state == NULL || iam->conf == NULL) {
        return false;
    }
    nn_string_set_init(&iam->notificationCategories, nm_iam_allocator_get());

    nn_vector_init(&iam->authorizedConnections, sizeof(struct nm_iam_authorized_connection), nm_iam_allocator_get());

    if (nm_iam_auth_handler_init(&iam->authHandler, iam->device, iam) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nm_iam_pake_handler_init(&iam->pakeHandler, iam->device, iam) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nm_iam_connection_events_init(&iam->connEvents, iam->device, iam) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nm_iam_internal_init_coap_handlers(iam) != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(iam->logger, LOGM, "Failed to initialize IAM CoAP handlers");
        return false;
    }
    return true;
}

void nm_iam_deinit(struct nm_iam* iam)
{
    if (iam->mutex == NULL) {
        return;
    }
    nm_iam_lock(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);
    nm_iam_pake_handler_deinit(&iam->pakeHandler);
    nm_iam_connection_events_deinit(&iam->connEvents);

    nm_iam_internal_deinit_coap_handlers(iam);

    nm_iam_state_free(iam->state);
    nm_iam_configuration_free(iam->conf);
    nn_string_set_deinit(&iam->notificationCategories);
    nn_vector_deinit(&iam->authorizedConnections);
    nm_iam_unlock(iam);

    nabto_device_threads_free_mutex(iam->mutex);
}


void nm_iam_stop(struct nm_iam* iam)
{
    nm_iam_lock(iam);
    nm_iam_internal_stop(iam);
    nm_iam_unlock(iam);
}


bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributesIn)
{
    bool status = 0;
    nm_iam_lock(iam);
    status = nm_iam_internal_check_access(iam, ref, action, attributesIn);
    nm_iam_unlock(iam);
    return status;
}



void nm_iam_set_state_changed_callback(struct nm_iam* iam, nm_iam_state_changed stateChanged, void* data)
{
    nm_iam_lock(iam);
    iam->changeCallback.stateChanged = stateChanged;
    iam->changeCallback.stateChangedData = data;
    nm_iam_unlock(iam);
}

bool nm_iam_load_configuration(struct nm_iam* iam, struct nm_iam_configuration* conf)
{
    bool status = 0;
    nm_iam_lock(iam);
    status = nm_iam_internal_load_configuration(iam, conf);
    nm_iam_unlock(iam);
    return status;
}

bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state)
{
    bool status = 0;
    nm_iam_lock(iam);
    status = nm_iam_internal_load_state(iam, state);
    nm_iam_unlock(iam);
    return status;
}

struct nm_iam_state* nm_iam_dump_state(struct nm_iam* iam)
{
    nm_iam_lock(iam);
    struct nm_iam_state* copy = nm_iam_state_copy(iam->state);
    nm_iam_unlock(iam);
    return copy;
}

enum nm_iam_error nm_iam_set_notification_categories(struct nm_iam* iam, struct nn_string_set* categories)
{
    nm_iam_lock(iam);
    nn_string_set_clear(&iam->notificationCategories);
    const char* s = NULL;
    NN_STRING_SET_FOREACH(s, categories) {
        if (!nn_string_set_insert(&iam->notificationCategories, s)) {
            nn_string_set_clear(&iam->notificationCategories);
            nm_iam_unlock(iam);
            return NM_IAM_ERROR_INTERNAL;
        }
    }
    nm_iam_unlock(iam);
    return NM_IAM_ERROR_OK;
}

void nm_iam_set_username_max_length(struct nm_iam* iam, size_t len)
{
    iam->usernameMaxLength = len;
}


void nm_iam_set_display_name_max_length(struct nm_iam* iam, size_t len)
{
    iam->displayNameMaxLength = len;
}

void nm_iam_set_password_min_length(struct nm_iam* iam, size_t len)
{
    iam->passwordMinLength = len;
}

void nm_iam_set_password_max_length(struct nm_iam* iam, size_t len)
{
    iam->passwordMaxLength = len;
}


void nm_iam_set_fcm_token_max_length(struct nm_iam* iam, size_t len)
{
    iam->fcmTokenMaxLength = len;
}


void nm_iam_set_fcm_project_id_max_length(struct nm_iam* iam, size_t len)
{
    iam->fcmProjectIdMaxLength = len;
}

void nm_iam_set_oauth_subject_max_length(struct nm_iam* iam, size_t len)
{
    iam->oauthSubjectMaxLength = len;
}

void nm_iam_set_sct_max_length(struct nm_iam* iam, size_t len)
{
    iam->sctMaxLength = len;
}

void nm_iam_set_friendly_name_max_length(struct nm_iam* iam, size_t len)
{
    iam->friendlyNameMaxLength = len;
}

void nm_iam_set_max_users(struct nm_iam* iam, size_t n)
{
    iam->maxUsers = n;
}

/**
 * Enable/disalbe open pairing.
 */
void nm_iam_set_local_open_pairing(struct nm_iam* iam, bool enabled)
{
    nm_iam_lock(iam);
    iam->state->localOpenPairing = enabled;
    nm_iam_internal_state_has_changed(iam);
    nm_iam_unlock(iam);
    nm_iam_internal_do_callbacks(iam);
}

void nm_iam_set_password_open_pairing(struct nm_iam* iam, bool enabled)
{
    nm_iam_lock(iam);
    iam->state->passwordOpenPairing = enabled;
    nm_iam_internal_state_has_changed(iam);
    nm_iam_unlock(iam);
    nm_iam_internal_do_callbacks(iam);
}

void nm_iam_set_password_invite_pairing(struct nm_iam* iam, bool enabled)
{
    nm_iam_lock(iam);
    iam->state->passwordInvitePairing = enabled;
    nm_iam_internal_state_has_changed(iam);
    nm_iam_unlock(iam);
    nm_iam_internal_do_callbacks(iam);
}

void nm_iam_set_local_initial_pairing(struct nm_iam* iam, bool enabled)
{
    nm_iam_lock(iam);
    iam->state->localInitialPairing = enabled;
    nm_iam_internal_state_has_changed(iam);
    nm_iam_unlock(iam);
    nm_iam_internal_do_callbacks(iam);
}

/**
 * Manage the user database at runtime from the application
 */
enum nm_iam_error nm_iam_create_user(struct nm_iam* iam, const char* username)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_create_user(iam, username);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_fingerprint(iam, username, fingerprint);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_add_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint, const char* fingerprintName)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_add_user_fingerprint(iam, username, fingerprint, fingerprintName);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_remove_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_remove_user_fingerprint(iam, username, fingerprint);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_sct(struct nm_iam* iam, const char* username, const char* sct)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_sct(iam, username, sct);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_password(struct nm_iam* iam, const char* username, const char* password)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_password(iam, username, password);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_role(struct nm_iam* iam, const char* username, const char* role)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_role(iam, username, role);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_display_name(struct nm_iam* iam, const char* username, const char* displayName)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_display_name(iam, username, displayName);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_fcm_token(struct nm_iam* iam, const char* username, const char* token)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_fcm_token(iam, username, token);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_fcm_project_id(struct nm_iam* iam, const char* username, const char* id)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_fcm_project_id(iam, username, id);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_notification_categories(struct nm_iam* iam, const char* username, struct nn_string_set* categories)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_notification_categories(iam, username, categories);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_set_user_oauth_subject(struct nm_iam* iam, const char* username, const char* subject)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_set_user_oauth_subject(iam, username, subject);
    nm_iam_unlock(iam);
    return ec;
}



enum nm_iam_error nm_iam_delete_user(struct nm_iam* iam, const char* username)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_delete_user(iam, username);
    nm_iam_unlock(iam);
    return ec;
}

enum nm_iam_error nm_iam_authorize_connection(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* username)
{
    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    nm_iam_lock(iam);
    ec = nm_iam_internal_authorize_connection(iam, ref, username);
    nm_iam_unlock(iam);
    return ec;

}

