// benchmark_client_rss.c
// Kernel-side TCP load generator with per-phase accounting.
//
// The previous version conflated "connect issued" with "connection
// established": a socket whose connect() failed silently (EADDRNOTAVAIL,
// SYN dropped, server backlog full) was counted the same as one that
// completed a real TCP handshake. This rewrite tracks each connection
// through its lifecycle and reports a breakdown:
//
//   socket()    failures          (likely EMFILE — raise ulimit -n)
//   bind()      failures          (port collision / TIME_WAIT / kernel-held)
//   connect()   immediate failures (EADDRNOTAVAIL, ENETUNREACH, etc.)
//   handshake   failures          (SYN-RST, SYN drop + giveup, EPOLLERR)
//   established                   <-- the number you actually want
//   completed_ok                  (got the response, saw FIN)
//   completed_err                 (epoll error after establishing)
//   still_pending (timed out)
//
// Conservation: bind_fail + connect_immediate_fail + socket_fail +
//               handshake_fail + established == NUM_CONN
// And:          completed_ok + completed_err + still_pending == established

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <time.h>

#define MAX_EVENTS    10000
#define NUM_CONN      8000        // Set to your target
#define TARGET_IP     "10.10.1.1"
#define TARGET_PORT   80
#define OVERALL_TIMEOUT_MS 30000  // hard cap on wait loop, so we always print

enum conn_status {
    CONN_PENDING = 0,   // socket in epoll, awaiting handshake completion
    CONN_ESTABLISHED,   // handshake done, request sent
    CONN_DONE_OK,       // got response, server closed cleanly
    CONN_DONE_ERR,      // failed at handshake or after
};

struct conn {
    int fd;
    enum conn_status status;
    int err;            // last errno seen (for diagnostics)
};

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint16_t get_random_port(void) {
    return (uint16_t)((rand() % (65535 - 1024)) + 1024);
}

// Returns:
//    0  on socket-created and connect() issued (fd in *out_fd)
//   -1  bind() exhausted retries
//   -2  connect() returned a real (non-EINPROGRESS) error immediately
//   -3  socket() itself failed (likely EMFILE / fd limit)
// errno is preserved on failure paths so the caller can log it.
static int create_connection(int *out_fd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -3;

    set_nonblocking(sock);

    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,  &flag, sizeof(flag));
    /* Allow rebinding ports stuck in TIME_WAIT from previous runs. Doesn't
     * help with ports the kernel currently has handed to other live
     * sockets — those still EADDRINUSE. */
    setsockopt(sock, SOL_SOCKET,  SO_REUSEADDR, &flag, sizeof(flag));

    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family      = AF_INET;
    src_addr.sin_addr.s_addr = INADDR_ANY;

    int tries = 0;
    while (1) {
        src_addr.sin_port = htons(get_random_port());
        if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) == 0)
            break;
        if (++tries > 100) {
            int saved = errno;
            close(sock);
            errno = saved;
            return -1;
        }
    }

    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port   = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &dst_addr.sin_addr);

    int rc = connect(sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if (rc < 0 && errno != EINPROGRESS) {
        /* Real failure at connect() time. EINPROGRESS is the normal
         * non-blocking case — handshake is now in flight, completion
         * (or failure) will surface via EPOLLOUT + SO_ERROR. */
        int saved = errno;
        close(sock);
        errno = saved;
        return -2;
    }

    *out_fd = sock;
    return 0;
}

int main(void) {
    srand((unsigned)time(NULL));

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create"); return 1; }

    struct conn *conns = calloc(NUM_CONN, sizeof(*conns));
    if (!conns) { perror("calloc"); return 1; }

    int socket_fail            = 0;
    int bind_fail              = 0;
    int connect_immediate_fail = 0;
    int created                = 0;   // sockets that made it into epoll

    /* Sample the first few errnos for each failure class so the user has
     * a hint about *why* it failed without us spamming stderr 8000 times. */
    int sample_bind_errno = 0, sample_connect_errno = 0, sample_socket_errno = 0;

    for (int i = 0; i < NUM_CONN; i++) {
        int fd = -1;
        int rc = create_connection(&fd);
        if (rc == -3) { if (!sample_socket_errno)  sample_socket_errno  = errno; socket_fail++; continue; }
        if (rc == -1) { if (!sample_bind_errno)    sample_bind_errno    = errno; bind_fail++;   continue; }
        if (rc == -2) { if (!sample_connect_errno) sample_connect_errno = errno; connect_immediate_fail++; continue; }

        conns[created].fd     = fd;
        conns[created].status = CONN_PENDING;
        conns[created].err    = 0;

        struct epoll_event ev;
        ev.data.ptr = &conns[created];
        ev.events   = EPOLLOUT | EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            perror("epoll_ctl ADD");
            close(fd);
            continue;
        }
        created++;
    }

    printf("Pre-loop: requested=%d socket_fail=%d bind_fail=%d connect_immediate_fail=%d in_epoll=%d\n",
           NUM_CONN, socket_fail, bind_fail, connect_immediate_fail, created);
    if (socket_fail)            printf("  sample socket() errno: %d (%s)\n",  sample_socket_errno,  strerror(sample_socket_errno));
    if (bind_fail)              printf("  sample bind() errno:   %d (%s)\n",  sample_bind_errno,    strerror(sample_bind_errno));
    if (connect_immediate_fail) printf("  sample connect() errno:%d (%s)\n",  sample_connect_errno, strerror(sample_connect_errno));

    const char *request =
        "GET /index.html HTTP/1.1\r\n"
        "Host: 10.10.1.1\r\n"
        "Connection: close\r\n\r\n";
    const size_t request_len = strlen(request);

    int established    = 0;   // handshake completed AND request sent
    int handshake_fail = 0;
    int done_ok        = 0;
    int done_err       = 0;
    int finished       = 0;   // total connections removed from in-flight set

    /* Sample errnos for handshake failures too. */
    int sample_handshake_errno = 0;

    struct epoll_event events[MAX_EVENTS];
    struct timespec start_time, end_time, deadline_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    deadline_ts = start_time;
    deadline_ts.tv_sec += OVERALL_TIMEOUT_MS / 1000;

    while (finished < created) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms_left = (deadline_ts.tv_sec - now.tv_sec) * 1000L +
                       (deadline_ts.tv_nsec - now.tv_nsec) / 1000000L;
        if (ms_left <= 0) {
            fprintf(stderr,
                "Overall timeout (%d ms) — %d still in flight; printing partial results\n",
                OVERALL_TIMEOUT_MS, created - finished);
            break;
        }

        int wait_ms = ms_left > 1000 ? 1000 : (int)ms_left;
        int n = epoll_wait(epfd, events, MAX_EVENTS, wait_ms);

        for (int i = 0; i < n; i++) {
            struct conn *c = (struct conn*)events[i].data.ptr;
            int fd = c->fd;

            /* Error path: EPOLLERR/EPOLLHUP is terminal. SO_ERROR tells
             * us why. If we hit this while still PENDING, the handshake
             * never completed (server RST'd, SYN-ACK never came, etc.). */
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                int err = 0; socklen_t sl = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl);
                c->err = err;
                if (c->status == CONN_PENDING) {
                    handshake_fail++;
                    if (!sample_handshake_errno) sample_handshake_errno = err;
                } else if (c->status == CONN_ESTABLISHED) {
                    done_err++;
                }
                c->status = CONN_DONE_ERR;
                close(fd);
                finished++;
                continue;
            }

            /* Handshake completion: first EPOLLOUT after EINPROGRESS.
             * SO_ERROR == 0 means real success; nonzero means the SYN
             * went out but the connection failed (e.g. ECONNREFUSED,
             * ETIMEDOUT). This is the *only* place a connection is
             * promoted from PENDING to ESTABLISHED. */
            if ((events[i].events & EPOLLOUT) && c->status == CONN_PENDING) {
                int err = 0; socklen_t sl = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl) < 0 || err != 0) {
                    c->err = err;
                    c->status = CONN_DONE_ERR;
                    handshake_fail++;
                    if (!sample_handshake_errno) sample_handshake_errno = err;
                    close(fd);
                    finished++;
                    continue;
                }
                /* Truly connected. Send the request and stop watching for OUT. */
                ssize_t w = send(fd, request, request_len, 0);
                (void)w;  /* small request — fits in TCP send buffer */
                c->status = CONN_ESTABLISHED;
                established++;

                struct epoll_event ev;
                ev.data.ptr = c;
                ev.events   = EPOLLIN | EPOLLET;
                epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
            }

            /* Read path: drain (EPOLLET requires reading until EAGAIN). */
            if (events[i].events & EPOLLIN) {
                char buf[4096];
                while (1) {
                    int r = (int)recv(fd, buf, sizeof(buf), 0);
                    if (r == 0) {
                        c->status = CONN_DONE_OK;
                        done_ok++;
                        close(fd);
                        finished++;
                        break;
                    } else if (r < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        c->err = errno;
                        c->status = CONN_DONE_ERR;
                        done_err++;
                        close(fd);
                        finished++;
                        break;
                    }
                    /* r > 0: data received, keep draining. */
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    int still_pending = created - finished;

    printf("\n==================== Results ====================\n");
    printf("Requested connections        : %d\n", NUM_CONN);
    printf("  socket() failures          : %d\n", socket_fail);
    printf("  bind() failures            : %d\n", bind_fail);
    printf("  connect() immediate fail   : %d\n", connect_immediate_fail);
    printf("Connect()s issued (in epoll) : %d\n", created);
    printf("  handshake failed           : %d", handshake_fail);
    if (handshake_fail) printf("    (sample errno %d: %s)", sample_handshake_errno, strerror(sample_handshake_errno));
    printf("\n");
    printf("  ESTABLISHED (request sent) : %d   <-- truly connected count\n", established);
    printf("    completed cleanly        : %d\n", done_ok);
    printf("    completed with error     : %d\n", done_err);
    printf("    still in flight (timeout): %d\n", still_pending);
    printf("Elapsed                      : %.4f s\n", elapsed);
    if (elapsed > 0) {
        printf("Establishment rate           : %.2f /s\n", established / elapsed);
        printf("Completion rate (ok only)    : %.2f /s\n", done_ok / elapsed);
    }

    /* Sanity: phases must add up. If they don't, there's a counter bug. */
    int sum = socket_fail + bind_fail + connect_immediate_fail
            + handshake_fail + established;
    if (sum != NUM_CONN) {
        printf("WARN: phase counters sum to %d, expected %d\n", sum, NUM_CONN);
    }
    printf("=================================================\n");

    free(conns);
    return 0;
}
