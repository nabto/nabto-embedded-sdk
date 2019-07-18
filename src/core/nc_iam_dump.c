#include "nc_iam_dump.h"

#include <cbor.h>


void nc_iam_dump_users(struct nc_iam* iam, CborEncoder* encoder);
void nc_iam_dump_user(struct nc_iam_user* iam, CborEncoder*);


np_error_code nc_iam_dump(struct nc_iam* iam, void* buffer, size_t bufferLength, size_t* used)
{
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, bufferLength, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "users");
    nc_iam_dump_users(iam, &map);

    cbor_encoder_close_container(&encoder, &map);
    // TODO test for error
    return NABTO_EC_OK;
}


void nc_iam_dump_users(struct nc_iam* iam, CborEncoder* encoder)
{
    CborEncoder users;
    cbor_encoder_create_map(encoder, &users, CborIndefiniteLength);
    struct nc_iam_list_entry* iterator = iam->users.sentinel.next;
    while(iterator != &iam->users.sentinel) {
        struct nc_iam_user* user = iterator->item;

        cbor_encode_text_stringz(&users, user->id);
        nc_iam_dump_user(user, &users);

        iterator = iterator->next;
    }
    cbor_encoder_close_container(encoder, &users);
}

void nc_iam_dump_user(struct nc_iam_user* user, CborEncoder* encoder)
{
    CborEncoder map;

    cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "roles");
    {
        CborEncoder roles;
        cbor_encoder_create_array(&map, &roles, CborIndefiniteLength);
        struct nc_iam_list_entry* iterator = user->roles.sentinel.next;
        while(iterator != &user->roles.sentinel) {
            struct nc_iam_role* role = iterator->item;
            cbor_encode_text_stringz(&roles, role->name);
            iterator = iterator->next;
        }

        cbor_encoder_close_container(&map, &roles);
    }

    cbor_encoder_close_container(encoder, &map);
}



np_error_code nc_iam_load(struct nc_iam* iam, void* cbor, size_t cborLength);
