#ifndef _NC_IAM_UTIL_H_
#define _NC_IAM_UTIL_H_

struct nc_iam_list_entry;
struct nc_iam_list_entry {
    struct nc_iam_list_entry* next;
    struct nc_iam_list_entry* prev;
    void* item;
};

struct nc_iam_list {
    struct nc_iam_list_entry sentinel;
};


void nc_iam_list_init(struct nc_iam_list* list);
void nc_iam_list_clear(struct nc_iam_list* list);
void nc_iam_list_insert(struct nc_iam_list* list, void* item);
void nc_iam_list_remove(struct nc_iam_list_entry* entry);
struct nc_iam_list_entry* nc_iam_list_entry_new();
void nc_iam_list_entry_free(struct nc_iam_list_entry* entry);

#endif
