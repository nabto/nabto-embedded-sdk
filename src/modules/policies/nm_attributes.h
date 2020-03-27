#ifndef _NM_ATTRIBUTES_H_
#define _NM_ATTRIBUTES_H_

struct nm_attributes_item {
    char* key;
    char* value;
};

struct nm_attributes {
    const char* key;
    nn_string_map value;
};

const char* nm_attributes_get_value_

#endif
