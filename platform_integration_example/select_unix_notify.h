#ifndef _SELECT_UNIX_NOTIFY_H_
#define _SELECT_UNIX_NOTIFY_H_

/**
 * Notify the platform that something has happened.
 *
 * @param data  A pointer to a struct select_unix_platform object.
 */
void select_unix_notify_platform(void* data);

#endif
