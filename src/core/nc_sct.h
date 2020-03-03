#ifndef _NC_SCT_H_
#define _NC_SCT_H_

typedef void (*nc_sct_callback)(np_error_code ec, void* userData);

/**
 * @return NABTO_EC_NO_OPERATION if everything is ok and no operation needs to be performed.
 *         NABTO_EC_OPERATION_STARTED if an upload is started
 *         NABTO_EC_OPERATION_IN_PROGRESS if an upload is already in progress.
 */
np_error_code nc_attacher_sct_upload(struct nc_attacher* attacher, nc_sct_callback cb);


#endif
