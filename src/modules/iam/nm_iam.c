#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"
#include "policies/nm_policy.h"

#include <nabto/nabto_device_experimental.h>

#include <nn/log.h>

#include <stdlib.h>
#include <time.h>

void nm_iam_lock(struct nm_iam* iam) {
    nabto_device_threads_mutex_lock(iam->mutex);
}
void nm_iam_unlock(struct nm_iam* iam) {
    nabto_device_threads_mutex_unlock(iam->mutex);
}

void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger)
{
    memset(iam, 0, sizeof(struct nm_iam));
    iam->mutex = nabto_device_threads_create_mutex();
    srand(time(0));
    iam->device = device;
    iam->logger = logger;

    nm_iam_auth_handler_init(&iam->authHandler, iam->device, iam);
    nm_iam_pake_handler_init(&iam->pakeHandler, iam->device, iam);

    nm_iam_internal_init_coap_handlers(iam);
}

void nm_iam_deinit(struct nm_iam* iam)
{
    nm_iam_lock(iam);
    nm_iam_internal_deinit_coap_handlers(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);
    nm_iam_pake_handler_deinit(&iam->pakeHandler);

    nm_iam_state_free(iam->state);
    nm_iam_configuration_free(iam->conf);
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
    bool status;
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
    bool status;
    nm_iam_lock(iam);
    status = nm_iam_internal_load_configuration(iam, conf);
    nm_iam_unlock(iam);
    return status;
}

bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state)
{
    bool status;
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
