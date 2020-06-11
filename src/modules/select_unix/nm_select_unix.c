#include "nm_select_unix.h"
#include "nm_select_unix_udp.h"
#include "nm_select_unix_tcp.h"

#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define LOG NABTO_LOG_MODULE_UDP

/**
 * Helper function declarations
 */
static void build_fd_sets();
static void* network_thread(void* data);

static int nm_select_unix_inf_wait(struct nm_select_unix* ctx);

static void nm_select_unix_read(struct nm_select_unix* ctx, int nfds);


/**
 * Api functions start
 */
np_error_code nm_select_unix_init(struct nm_select_unix* ctx)
{
    nn_llist_init(&ctx->udpSockets);
    nn_llist_init(&ctx->tcpSockets);
    ctx->stopped = false;
    ctx->thread = 0;
    if (pipe(ctx->pipefd) == -1) {
        NABTO_LOG_ERROR(LOG, "Failed to create pipe %s", errno);
        return NABTO_EC_UNKNOWN;
    }

    return NABTO_EC_OK;
}

void nm_select_unix_deinit(struct nm_select_unix* ctx)
{
    nm_select_unix_stop(ctx);
    close(ctx->pipefd[0]);
    close(ctx->pipefd[1]);

    if (ctx->thread != 0) {
        pthread_join(ctx->thread, NULL);
    }
}

void nm_select_unix_run(struct nm_select_unix* ctx)
{
    pthread_create(&ctx->thread, NULL, &network_thread, ctx);
}

void nm_select_unix_stop(struct nm_select_unix* ctx)
{
    if (ctx->stopped) {
        return;
    }
    ctx->stopped = true;
    nm_select_unix_notify(ctx);
}

int nm_select_unix_inf_wait(struct nm_select_unix* ctx)
{
    int nfds;
    build_fd_sets(ctx);
    nfds = select(NP_MAX(ctx->maxReadFd, ctx->maxWriteFd)+1, &ctx->readFds, &ctx->writeFds, NULL, NULL);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in select: (%i) '%s'", errno, strerror(errno));
    } else {
        NABTO_LOG_TRACE(LOG, "select returned with %i file descriptors", nfds);
    }
    return nfds;
}

int nm_select_unix_timed_wait(struct nm_select_unix* ctx, uint32_t ms)
{
    NABTO_LOG_TRACE(LOG, "timed wait %d", ms);
    int nfds;
    struct timeval timeout_val;
    timeout_val.tv_sec = (ms/1000);
    timeout_val.tv_usec = ((ms)%1000)*1000;
    build_fd_sets(ctx);
    nfds = select(NP_MAX(ctx->maxReadFd, ctx->maxWriteFd)+1, &ctx->readFds, &ctx->writeFds, NULL, &timeout_val);
    if (nfds < 0) {
        NABTO_LOG_ERROR(LOG, "Error in select wait: (%i) '%s'", errno, strerror(errno));
    }
    return nfds;
}

void nm_select_unix_read(struct nm_select_unix* ctx, int nfds)
{
    char one;
    NABTO_LOG_TRACE(LOG, "read: %i", nfds);

    if (FD_ISSET(ctx->pipefd[0], &ctx->readFds)) {
        read(ctx->pipefd[0], &one, 1);
    }
    if (FD_ISSET(ctx->pipefd[1], &ctx->readFds)) {
        read(ctx->pipefd[1], &one, 1);
    }

    nm_select_unix_udp_handle_select(ctx, nfds);
    nm_select_unix_tcp_handle_select(ctx, nfds);
}

/**
 * Helper functions start
 */

void build_fd_sets(struct nm_select_unix* ctx)
{
    FD_ZERO(&ctx->readFds);
    FD_ZERO(&ctx->writeFds);
    ctx->maxReadFd = 0;
    ctx->maxWriteFd = 0;
    FD_SET(ctx->pipefd[0], &ctx->readFds);
    ctx->maxReadFd = NP_MAX(ctx->maxReadFd, ctx->pipefd[0]);
    FD_SET(ctx->pipefd[1], &ctx->readFds);
    ctx->maxReadFd = NP_MAX(ctx->maxReadFd, ctx->pipefd[1]);

    nm_select_unix_udp_build_fd_sets(ctx);

    nm_select_unix_tcp_build_fd_sets(ctx);
}

void nm_select_unix_notify(struct nm_select_unix* ctx)
{
    write(ctx->pipefd[1], "1", 1);
}

void* network_thread(void* data)
{
    struct nm_select_unix* ctx = data;
    while(true) {
        int nfds;

        if (ctx->stopped) {
            return NULL;
        } else {
            // Wait for events.
            nfds = nm_select_unix_inf_wait(ctx);
            nm_select_unix_read(ctx, nfds);
        }
    }
    return NULL;
}
