#ifndef _NM_IAM_PDP_H_
#define _NM_IAM_PDP_H_

/**
 * @return NABTO_EC_OK
 *
 */
typedef void (*nm_iam_pdp_decision)(const np_error_code ec, void* userData);

void nm_iam_pdp_decide(uint64_t connectionId, const char* action, void* objectAttributes, size_t objectAttributesSize, nm_iam_pdp_decision* cb, void* userData);

#endif
