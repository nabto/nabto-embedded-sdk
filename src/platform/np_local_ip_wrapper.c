#include "np_local_ip_wrapper.h"

#include "np_logging.h"
#include "np_logging_defines.h"

#define LOG NABTO_LOG_MODULE_PLATFORM

size_t np_local_ip_get_local_ips(struct np_local_ip* obj,  struct np_ip_address *addrs, size_t addrsSize)
{
    if (obj->mptr == NULL) {
        NABTO_LOG_ERROR(LOG, "Missing local ip implementation");
        return 0;
    } else {
        return obj->mptr->get_local_ips(obj, addrs, addrsSize);
    }
}
