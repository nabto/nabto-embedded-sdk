#ifndef _NM_IAM_INTERNAL_H_
#define _NM_IAM_INTERNAL_H_

char* nm_iam_next_user_id(struct nm_iam* iam);
struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint);
struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr);
struct nm_policy* nm_iam_find_policy(struct nm_iam* iam, const char* policyStr);

struct nm_iam_user* nm_iam_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* name);
struct nm_iam_user* nm_iam_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);
#endif
