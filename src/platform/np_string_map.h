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
struct np_string_map_item* np_string_map_get(const struct np_string_map* map, const char* key);
struct np_string_map_item* np_string_map_getn(const struct np_string_map* map, const char* key, size_t keyLength);

/**
 * insert an item into a string map
 */
np_error_code np_string_map_insert(struct np_string_map* map, const char* key, const char* value);


void np_string_map_init(struct np_string_map* map);
void np_string_map_deinit(struct np_string_map* map);

void np_string_map_destroy_item(struct np_string_map_item* item);

bool np_string_map_empty(const struct np_string_map* map);

// iterator
void np_string_map_front(const struct np_string_map* map, struct np_string_map_iterator* it);
struct np_string_map_iterator np_string_map_front2(const struct np_string_map* map);
bool np_string_map_end(const struct np_string_map_iterator* it);
void np_string_map_next(struct np_string_map_iterator* it);

struct np_string_map_item* np_string_map_get_element(const struct np_string_map_iterator* it);

#define NP_STRING_MAP_FOREACH(item, map) for(struct np_string_map_iterator it = np_string_map_front2(map); item = np_string_map_get_element(&it), !np_string_map_end(&it); np_string_map_next(&it))

#ifdef __cplusplus
} //extern "C"
#endif

#endif
