#include "nm_iam_util.h"

bool nm_iam_find_action_in_list(struct nm_iam_list* actions, struct nm_iam_action* action)
{
    struct nm_iam_list_entry* iterator = actions->sentinel.next;
    while (iterator != &actions->sentinel) {
        struct nm_iam_action* entry = (struct nm_iam_action*)iterator->item;
        if (entry == action) {
            return true;
        }
        iterator = iterator->next;
    }
    return false;
}
