#ifndef _NM_COMMUNICATION_BUFFER_H_
#define _NM_COMMUNICATION_BUFFER_H_

#ifndef NABTO_COMMUNICATION_BUFFER_LENGTH
#define NABTO_COMMUNICATION_BUFFER_LENGTH 1500
#endif

struct np_platform;

#ifdef __cplusplus
extern "C" {
#endif

void nm_communication_buffer_init(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NM_COMMUNICATION_BUFFER_H_
