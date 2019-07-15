#ifndef _NM_IAM_CBOR_H_
#define _NM_IAM_CBOR_H_

#include "nm_iam.h"

void nm_iam_user_list_as_cbor(struct nm_iam* iam, void** cbor, size_t* cborLength);

#endif
