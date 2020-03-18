#include "np_string_map.h"

#include <stdlib.h>
#include <string.h>

void np_string_map_init(struct np_string_map* map)
{
    np_list_init(&map->items);
}

void np_string_map_deinit(struct np_string_map* map)
{
    struct np_list_iterator it;
    np_list_front(&map->items, &it);
    while(!np_list_end(&it))
    {
        struct np_string_map_item* item = np_list_get_element(&it);
        np_list_next(&it);
        np_string_map_destroy_item(item);
    }
}

void np_string_map_destroy_item(struct np_string_map_item* item)
{
    np_list_erase_item(&item->item);
    free(item->key);
    free(item->value);
    free(item);
}


np_error_code np_string_map_insert(struct np_string_map* map, const char* key, const char* value)
{
    if (np_string_map_get(map, key) != NULL) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    struct np_string_map_item* item = calloc(1, sizeof(struct np_string_map_item));
    char* keyDup = strdup(key);
    char* valueDup = strdup(value);
    if (item == NULL || keyDup == NULL || valueDup == NULL) {
        free(item); free(keyDup); free(valueDup);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    item->key = keyDup;
    item->value = valueDup;

    np_list_append(&map->items, &item->item, item);
    return NABTO_EC_OK;
}

struct np_string_map_item* np_string_map_get(const struct np_string_map* map, const char* key)
{
    struct np_list_iterator it;
    for (np_list_front(&map->items, &it);
         !np_list_end(&it);
         np_list_next(&it))
    {
        struct np_string_map_item* item = np_list_get_element(&it);
        if (strcmp(item->key, key) == 0) {
            return item;
        }
    }
    return NULL;
}

struct np_string_map_item* np_string_map_getn(const struct np_string_map* map, const char* key, size_t keyLength)
{
    struct np_list_iterator it;
    for (np_list_front(&map->items, &it);
         !np_list_end(&it);
         np_list_next(&it))
    {
        struct np_string_map_item* item = np_list_get_element(&it);
        if (strncmp(item->key, key, keyLength) == 0) {
            return item;
        }
    }
    return NULL;
}


bool np_string_map_empty(const struct np_string_map* map)
{
    return np_list_empty(&map->items);
}

// iterator
void np_string_map_front(const struct np_string_map* map, struct np_string_map_iterator* it)
{
    np_list_front(&map->items, &it->it);
}

struct np_string_map_iterator np_string_map_front2(const struct np_string_map* map)
{
    struct np_string_map_iterator it;
    np_list_front(&map->items, &it.it);
    return it;
}

bool np_string_map_end(const struct np_string_map_iterator* it)
{
    return np_list_end(&it->it);
}

void np_string_map_next(struct np_string_map_iterator* it)
{
    np_list_next(&it->it);
}

struct np_string_map_item* np_string_map_get_element(const struct np_string_map_iterator* it)
{
    return np_list_get_element(&it->it);
}
