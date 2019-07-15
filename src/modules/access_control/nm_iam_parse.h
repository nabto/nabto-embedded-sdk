#ifndef _NM_IAM_PARSE_H_
#define _NM_IAM_PARSE_H_

#include "nm_iam.h"

#include <stdbool.h>
#include <string.h>

// parse a policy json document.
struct nm_iam_policy* nm_iam_parse_policy(struct nm_iam* iam, const char* json);

void nm_iam_parse_config(struct nm_iam* iam, const char* json);

// cJSON* nm_iam_write_config(struct nm_iam* iam);

#endif
