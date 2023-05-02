#include "nm_epoll.h"

#include <string.h>

#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>

#include <sys/socket.h>
#include <unistd.h>
#include "errno.h"

#include <pthread.h>

#include <api/nabto_device_threads.h>

#define LOG NABTO_LOG_MODULE_UDP

static void* epoll_loop(void* arg);


np_error_code nm_epoll_init(struct nm_epoll* ctx, struct nabto_device_mutex* coreMutex)
{
    memset(ctx, 0, sizeof(struct nm_epoll));

    ctx->coreMutex = coreMutex;
    ctx->ts = nm_epoll_ts_get_impl(ctx);
    ctx->running = true;

    ctx->epollFd = epoll_create(1);
    if (ctx->epollFd == -1) {
        NABTO_LOG_ERROR(LOG, "Could not create epoll socket %s", strerror(errno));
        return NABTO_EC_UNKNOWN;
    }

    ctx->queueMutex = nabto_device_threads_create_mutex();
    ctx->handleEventsMutex = nabto_device_threads_create_mutex();

    nm_epoll_ts_update(ctx);

    nm_event_queue_init(&ctx->eventQueue);
    nm_epoll_notify_init(ctx);

    return NABTO_EC_OK;
}

void nm_epoll_deinit(struct nm_epoll* ctx) 
{
    nabto_device_threads_free_mutex(ctx->queueMutex);
    nabto_device_threads_free_mutex(ctx->handleEventsMutex);
}

#define MAX_EVENTS 10

np_error_code nm_epoll_run(struct nm_epoll* epoll) {
    pthread_create(&epoll->thread, NULL, epoll_loop, epoll);
    return NABTO_EC_OK;
}

void nm_epoll_stop_blocking(struct nm_epoll* ctx)
{
    ctx->running = false;
    nm_epoll_notify(ctx);
    void* retval;
    pthread_join(ctx->thread, &retval);
}

void set_handle_events(struct nm_epoll* ctx) 
{
    nabto_device_threads_mutex_lock(ctx->handleEventsMutex);
    ctx->handleEvents = true;
    nabto_device_threads_mutex_unlock(ctx->handleEventsMutex);
}

void reset_handle_events(struct nm_epoll* ctx) 
{
    nabto_device_threads_mutex_lock(ctx->handleEventsMutex);
    ctx->handleEvents = false;
    nabto_device_threads_mutex_unlock(ctx->handleEventsMutex);
}

void* epoll_loop(void* arg)
{
    struct nm_epoll* ctx = arg;
    struct epoll_event events[MAX_EVENTS];
    set_handle_events(ctx);
    while(ctx->running) {

        bool moreEvents = true;
        while(moreEvents) {
            moreEvents = nm_epoll_event_queue_handle_event(ctx);
        }

        int32_t millis = -1;
        if (nm_epoll_event_queue_get_next_timed_event(ctx, &millis)) {
            if (millis < 0) {
                millis = 0;
            }
        }

        reset_handle_events(ctx);
        
        int ready = epoll_wait(ctx->epollFd, events, MAX_EVENTS, millis);
        nm_epoll_ts_update(ctx);

        set_handle_events(ctx);
        if (ready == -1) {
            NABTO_LOG_ERROR(LOG, "epoll wait error %s", strerror(errno));
        }

        for (int i = 0; i < ready; i++) {
            struct nm_epoll_handle* handle = events[i].data.ptr;
            if (handle->epollType == NM_EPOLL_TYPE_NOTIFY) {
                struct nm_epoll_notify* notify = events[i].data.ptr;
                uint8_t buffer[64];
                recv(notify->readSocket, buffer, sizeof(buffer), MSG_DONTWAIT);
            }
            if (handle->epollType == NM_EPOLL_TYPE_UDP) {
                struct np_udp_socket* s = events[i].data.ptr;
                nm_epoll_udp_handle_event(s, events[i].events);
            }
            if (handle->epollType == NM_EPOLL_TYPE_TCP) {
                struct np_tcp_socket* s = events[i].data.ptr;
                nm_epoll_tcp_handle_event(s, events[i].events);
            }
        }
        
    }
    reset_handle_events(ctx);
    return NULL;
}


void nm_epoll_notify_init(struct nm_epoll* epoll)
{
    int fds[2];
    int status = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (status == -1) {
        // TODO
    }

    epoll->notify.epollType = NM_EPOLL_TYPE_NOTIFY;
    epoll->notify.readSocket = fds[0];
    epoll->notify.writeSocket = fds[1];

    struct epoll_event e;
    e.events = EPOLLIN;
    e.data.ptr = &epoll->notify;

    status = epoll_ctl(epoll->epollFd, EPOLL_CTL_ADD, epoll->notify.readSocket, &e);
    if (status == -1) {
        NABTO_LOG_ERROR(LOG, "epoll_ctl error %s",strerror(errno));
    }
}

void nm_epoll_notify_deinit(struct nm_epoll* epoll)
{
    close(epoll->notify.readSocket);
    close(epoll->notify.writeSocket);
}

void nm_epoll_notify(struct nm_epoll* epoll) 
{
    uint8_t byte = 0x42;
    nabto_device_threads_mutex_lock(epoll->handleEventsMutex);
    if (!epoll->handleEvents) {
        send(epoll->notify.writeSocket, &byte, 1, MSG_DONTWAIT);
    }
    nabto_device_threads_mutex_unlock(epoll->handleEventsMutex);
}
