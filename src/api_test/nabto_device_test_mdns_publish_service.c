#include <nabto/nabto_device_test.h>
#include <api/nabto_device_defines.h>

#include <platform/np_mdns_wrapper.h>
#include <platform/np_heap.h>

#include <nn/string_set.h>
#include <nn/string_map.h>

void NABTO_DEVICE_API
nabto_device_test_mdns_publish_service(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    // Yes these leaks some memory.
    static struct nn_string_set subtypes;
    static struct nn_string_map txtItems;

    nn_string_set_init(&subtypes, np_get_default_allocator());
    nn_string_map_init(&txtItems, np_get_default_allocator());

    nn_string_set_insert(&subtypes, "pr-12345678-de-abcdefgh");
    nn_string_map_insert(&txtItems, "productid", "pr-12345678");
    nn_string_map_insert(&txtItems, "deviceid", "de-abcdefgh");

    np_mdns_publish_service(&dev->pl.mdns, 4242, "pr-12345678-de-abcdefgh", &subtypes, &txtItems);
}
