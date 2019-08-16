#include "nabto_api_future_queue.h"

#include <api/nabto_device_future.h>

#include <platform/np_logging.h>

void nabto_api_future_queue_execute_all(struct nabto_device_future** queue)
{
    struct nabto_device_future** head = (struct nabto_device_future**)queue;
    struct nabto_device_future* elm;
    NABTO_LOG_TRACE(NABTO_LOG_MODULE_API, "executing future callbacks. Head: %u", *head);
    if (*head == NULL ) {
        return;
    }
    while (*head != NULL) {
        elm = *head;
        *head = (*head)->next;
        nabto_device_future_resolve(elm);
        //elm->cb(elm->ec, elm->cbData);
    }

}

void nabto_api_future_queue_post(struct nabto_device_future** queue, struct nabto_device_future* fut)
{
    struct nabto_device_future** head = queue;
    fut->next = *head;
    *head = fut;
}
