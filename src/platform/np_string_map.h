#ifndef _NP_STRING_MAP_
#define _NP_STRING_MAP_

#include "np_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dynamic allocated map<string,string>
 */
struct np_string_map_item {
    struct np_list_item item;
    char* key;
    char* value;
};

struct np_string_map {
    struct np_list items;
};

/**
 * If an item with the key exists return it, else return NULL;
 */
struct np_string_map_item* np_string_map_get(struct np_string_map* map, const char* key);

/**
 * insert an item into a string map
 */
np_error_code np_string_map_insert(struct np_string_map* map, const char* key, const char* value);


void np_string_map_init(struct np_string_map* map);
void np_string_map_deinit(struct np_string_map* map);

void np_string_map_destroy_item(struct np_string_map_item* item);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
