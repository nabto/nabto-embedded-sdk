#include "nm_iam_cbor.h"

#include <cbor.h>



void nm_iam_user_list_as_cbor(struct nm_iam* iam, void** cbor, size_t* cborLength)
{
    CborEncoder encoder;
    CborEncoder users;

    uint8_t buffer[128];
    cbor_encoder_init(&encoder, buffer, 128, 0);
    cbor_encoder_create_array(&encoder, &users, CborIndefiniteLength);

    struct nm_iam_list_entry* iterator = iam->users.sentinel.next;
    while (iterator != &iam->users.sentinel) {
        struct nm_iam_user* user = (struct nm_iam_user*)iterator->item;
        cbor_encode_text_stringz(&users, user->name);
        iterator = iterator->next;
    }
    cbor_encoder_close_container(&encoder, &users);
}

bool nm_iam_has_user(struct nm_iam* iam, const char* userName)
{
    uint8_t buffer[1024];

    CborParser parser;
    CborValue value;
    cbor_parser_init(buffer, 1024, 0, &parser, &value);
    if (!cbor_value_is_map(&value)) {
        return false;
    }
    CborValue users;
    cbor_value_map_find_value(&value, "users", &users);
    if (!cbor_value_is_map(&users)) {
        return false;
    }

    CborValue user;
    cbor_value_map_find_value(&users, userName, &user);

    return true;
}
