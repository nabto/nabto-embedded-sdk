#ifndef _NM_POLICY_H_
#define _NM_POLICY_H_

struct nm_policy {
    char* id;
    struct np_vector statements;
};

void nm_policy_init(const char* id);

// TODO
void nm_policy_add_statement(struct nm_policy* policy);

#endif
