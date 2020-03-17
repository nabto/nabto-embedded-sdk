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

struct np_string_map_iterator {
    struct np_list_iterator it;
};

/**
 * If an item with the key exists return it, else return NULL;
 */
struct np_string_map_item* np_string_map_get(struct np_string_map* map, const char* key);
struct np_string_map_item* np_string_map_getn(struct np_string_map* map, const char* key, size_t keyLength);

/**
 * insert an item into a string map
 */
np_error_code np_string_map_insert(struct np_string_map* map, const char* key, const char* value);


void np_string_map_init(struct np_string_map* map);
void np_string_map_deinit(struct np_string_map* map);

void np_string_map_destroy_item(struct np_string_map_item* item);

bool np_string_map_empty(struct np_string_map* map);

// iterator
void np_string_map_front(struct np_string_map* map, struct np_string_map_iterator* it);
bool np_string_map_end(struct np_string_map_iterator* it);
void np_string_map_next(struct np_string_map_iterator* it);

struct np_string_map_item* np_string_map_get_element(struct np_string_map_iterator* it);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
