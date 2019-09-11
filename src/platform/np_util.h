#ifndef _NP_UTIL_H_
#define _NP_UTIL_H_

// Renamed MAX as NP_MAX, as it often gives problems with headers
// already defining MAX without testing for its existence and the
// header include order then becomes an issue.

#define NP_MAX(a,b) (((a)>(b))?(a):(b))

#endif
