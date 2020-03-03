#ifndef _NP_LIST_H_
#define _NP_LIST_H_

#include "np_error_code.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_list_item;

struct np_list_item {
    struct np_list_item* next;
    struct np_list_item* prev;

    void* element;
};

struct np_list {
    struct np_list_item sentinel;
};

struct np_list_iterator {
    struct np_list* list;
    struct np_list_item* item;
};

// malloc free list

void np_list_init(struct np_list* list);
void np_list_deinit(struct np_list* list);


// return true if the list is empty
bool np_list_empty(struct np_list* list);

// add an item to the end of the list
void np_list_append(struct np_list* list, struct np_list_item* item, void* element);

// erase an element from the list.
void np_list_erase_item(struct np_list_item* iterator);

void np_list_erase_iterator(struct np_list_iterator* iterator);

// return front element of the list or NULL if empty
void np_list_front(struct np_list* list, struct np_list_iterator* iterator);

void np_list_next(struct np_list_iterator* iterator);

bool np_list_end(struct np_list_iterator* iterator);

void* np_list_get_element(struct np_list_iterator* iterator);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
