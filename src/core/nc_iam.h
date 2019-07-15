#ifndef _NC_IAM_H_
#define _NC_IAM_H_

#include <stdint.h>
#include <stdbool.h>

struct nc_iam_fingerprint {
    struct nc_iam_user* user;
    uint8_t fingerprint[16];
};

struct nc_iam_list_entry;
struct nc_iam_list_entry {
    struct nc_iam_list_entry* next;
    struct nc_iam_list_entry* prev;
    void* item;
};

struct nc_iam_list {
    struct nc_iam_list_entry sentinel;
};


struct nc_iam {
    struct nc_iam_list fingerprints;
    struct nc_iam_list users;


    struct nc_iam_user* defaultUser;
};

struct nc_iam_user {

};

struct nc_iam_env {
    struct nc_iam* iam;
    struct nc_client_connection* connection;
    struct nc_iam_list attributes;
};

void nc_iam_init(struct nc_iam* iam);
void nc_iam_deinit(struct nc_iam* iam);

struct nc_iam_user* nc_iam_find_user(struct nc_iam* iam, uint8_t fingerprint[16]);

bool nc_iam_check_access(struct nc_iam_env* env, const char* action);


#endif
