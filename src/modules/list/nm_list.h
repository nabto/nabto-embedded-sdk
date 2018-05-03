#ifndef _NM_LIST_H_
#define _NM_LIST_H_

/*
 * THIS FILE IS CURRENTLY UNUSED, RECONSIDER ITS IMPORTANCE BEFORE USING
 * This file is based on the utlist.h file in unabto! check license
 * of that, and make a decision wether to take the whole file from
 * unabto, or make something our self.
 * currently the event_queue platform module implements its own 
 * list, consider using something from here.
 */

#include <assert.h>

#define DL_APPEND(head,add)                                                                    \
do {                                                                                           \
  if (head) {                                                                                  \
      (add)->prev = (head)->prev;                                                              \
      (head)->prev->next = (add);                                                              \
      (head)->prev = (add);                                                                    \
      (add)->next = NULL;                                                                      \
  } else {                                                                                     \
      (head)=(add);                                                                            \
      (head)->prev = (head);                                                                   \
      (head)->next = NULL;                                                                     \
  }                                                                                            \
} while (0)

#define DL_DELETE(head,del)                                                                    \
do {                                                                                           \
  assert((del)->prev != NULL);                                                                 \
  if ((del)->prev == (del)) {                                                                  \
      (head)=NULL;                                                                             \
  } else if ((del)==(head)) {                                                                  \
      (del)->next->prev = (del)->prev;                                                         \
      (head) = (del)->next;                                                                    \
  } else {                                                                                     \
      (del)->prev->next = (del)->next;                                                         \
      if ((del)->next) {                                                                       \
          (del)->next->prev = (del)->prev;                                                     \
      } else {                                                                                 \
          (head)->prev = (del)->prev;                                                          \
      }                                                                                        \
  }                                                                                            \
} while (0)

#define DL_FOREACH(head,el)                                                                    \
    for(el=head;el;el=(el)->next)

#endif // _NM_LIST_H_
