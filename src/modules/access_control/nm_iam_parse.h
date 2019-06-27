#ifndef _NM_IAM_PARSE_H_
#define _NM_IAM_PARSE_H_

// parse a policy json document.
bool nm_iam_parse_policy(struct nm_iam* iam, const char* json, size_t jsonLength);

#endif
