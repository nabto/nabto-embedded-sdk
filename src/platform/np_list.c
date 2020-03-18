#include "np_list.h"


void np_list_init(struct np_list* list)
{
    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
    list->sentinel.element = NULL;
}


void np_list_deinit(struct np_list* list)
{

}


// return true if the list is empty
bool np_list_empty(const struct np_list* list)
{
    return list->sentinel.next == &list->sentinel;
}

// add an item to the end of the list
void np_list_append(struct np_list* list, struct np_list_item* item, void* element)
{
    item->element = element;
    struct np_list_item* before = list->sentinel.prev;
    struct np_list_item* after = before->next;

    before->next = item;
    item->next = after;
    after->prev = item;
    item->prev = before;
}

// erase an element from the list.
void np_list_erase_item(struct np_list_item* item)
{
    struct np_list_item* before = item->prev;
    struct np_list_item* after = item->next;
    before->next = after;
    after->prev = before;

    item->prev = item;
    item->next = item;
}

void np_list_erase_iterator(struct np_list_iterator* iterator)
{
    np_list_erase_item(iterator->item);
}

// return front element of the list or NULL if empty
void np_list_front(const struct np_list* list, struct np_list_iterator* iterator)
{
    iterator->list = list;
    iterator->item = list->sentinel.next;
}

void np_list_next(struct np_list_iterator* iterator)
{
    iterator->item = iterator->item->next;
}

bool np_list_end(const struct np_list_iterator* iterator)
{
    return iterator->item == &iterator->list->sentinel;
}

void* np_list_get_element(const struct np_list_iterator* iterator)
{
    return iterator->item->element;
}
