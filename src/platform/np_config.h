#ifndef NP_CONFIG_H_
#define NP_CONFIG_H_

#if defined(NP_CONFIG_FILE)
#include NP_CONFIG_FILE
#endif

#ifndef NP_ALLOCATOR_FREE
#define NP_ALLOCATOR_FREE free
#endif

#ifndef NP_ALLOCATOR_CALLOC
#define NP_ALLOCATOR_CALLOC calloc
#endif

#endif
