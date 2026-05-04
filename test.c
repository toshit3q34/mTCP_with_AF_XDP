// benchmark_client_rss.c
// Kernel-side TCP load generator with per-phase accounting.
//
// Three explicit phases:
//   Phase 1 (UNTIMED): issue connect() for every requested connection.
//                      Track bind / immediate-connect failures.
//   Phase 2 (UNTIMED): single epoll_wait window (HANDSHAKE_TIMEOUT_MS)
//                      to let handshakes complete. Anything still in
//                      CONN_PENDING when the window closes is treated
//                      as a handshake failure — we do NOT retry.
//   Phase 3 (TIMED):   send the HTTP request on every ESTABLISHED
//                      connection, drain responses until each peer
//                      closes (FIN), or until REQUEST_TIMEOUT_MS.
//                      Throughput is computed exclusively from this
//                      window's elapsed time — handshake jitter is
//                      excluded from the number you report.
//
// Reported buckets:
//   socket() / bind() / connect() immediate failures   (Phase 1)
//   handshake_fail                                     (Phase 2)
//   established  <-- denominator for throughput        (after Phase 2)
//   completed_ok / completed_err / still_in_flight     (Phase 3)
//
// Conservation:
//   socket_fail + bind_fail + connect_immediate_fail +
//   handshake_fail + established == NUM_CONN
//   completed_ok + completed_err + still_in_flight == established
//
// Throughput = completed_ok / Phase-3 elapsed seconds.

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

#define MAX_EVENTS         10000
#define NUM_CONN           8000          // requested connection count
#define TARGET_IP          "10.10.1.1"
#define TARGET_PORT        80

// Single window to let TCP handshakes finish. After this expires, every
// still-PENDING socket is declared a handshake failure (no retries).
#define HANDSHAKE_TIMEOUT_MS  5000

// Hard cap on the request/response phase. Bounds total wall time so
// the program always prints results.
#define REQUEST_TIMEOUT_MS    30000

enum conn_status {
    CONN_PENDING = 0,   // socket in epoll, awaiting handshake completion
    CONN_ESTABLISHED,   // handshake done; ready to send
    CONN_DONE_OK,       // got response, server closed cleanly
    CONN_DONE_ERR,      // failed at handshake or after
};

struct conn {
    int fd;
    enum conn_status status;
    int err;            // last errno (diagnostic only)
};

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint16_t get_random_port(void) {
    return (uint16_t)((rand() % (65535 - 1024)) + 1024);
}

// Returns:
//    0  socket created and connect() issued (fd in *out_fd)
//   -1  bind() exhausted retries
//   -2  connect() returned a real (non-EINPROGRESS) error immediately
//   -3  socket() itself failed (likely EMFILE / fd limit)
// errno is preserved on failure paths.
static int create_connection(int *out_fd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -3;

    set_nonblocking(sock);

    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,  &flag, sizeof(flag));
    /* Allow rebinding ports stuck in TIME_WAIT from prior runs. Doesn't
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
        int saved = errno;
        close(sock);
        errno = saved;
        return -2;
    }

    *out_fd = sock;
    return 0;
}

/* Compute milliseconds remaining until `deadline` from `now` (both monotonic). */
static long ms_until(const struct timespec *deadline,
                     const struct timespec *now) {
    return (deadline->tv_sec - now->tv_sec) * 1000L +
           (deadline->tv_nsec - now->tv_nsec) / 1000000L;
}

int main(void) {
    srand((unsigned)time(NULL));

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create"); return 1; }

    struct conn *conns = calloc(NUM_CONN, sizeof(*conns));
    if (!conns) { perror("calloc"); return 1; }

    /* ============================================================
     * PHASE 1 — issue connect()s (UNTIMED for throughput purposes)
     * ============================================================ */

    int socket_fail            = 0;
    int bind_fail              = 0;
    int connect_immediate_fail = 0;
    int created                = 0;   // sockets that made it into epoll

    int sample_socket_errno = 0, sample_bind_errno = 0, sample_connect_errno = 0;

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
        ev.events   = EPOLLOUT | EPOLLET;   /* only OUT during handshake phase */
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            perror("epoll_ctl ADD");
            close(fd);
            continue;
        }
        created++;
    }

    printf("Phase 1 (issue connects): requested=%d socket_fail=%d bind_fail=%d connect_immediate_fail=%d in_epoll=%d\n",
           NUM_CONN, socket_fail, bind_fail, connect_immediate_fail, created);
    if (socket_fail)            printf("  sample socket() errno: %d (%s)\n", sample_socket_errno,  strerror(sample_socket_errno));
    if (bind_fail)              printf("  sample bind() errno:   %d (%s)\n", sample_bind_errno,    strerror(sample_bind_errno));
    if (connect_immediate_fail) printf("  sample connect() errno:%d (%s)\n", sample_connect_errno, strerror(sample_connect_errno));

    /* ============================================================
     * PHASE 2 — wait for handshakes to complete (UNTIMED)
     * Single window. No retries. Anything still PENDING when
     * HANDSHAKE_TIMEOUT_MS elapses is counted as handshake_fail.
     * ============================================================ */

    int handshake_fail = 0;
    int established   = 0;
    int sample_handshake_errno = 0;

    struct timespec t_phase2_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_phase2_start);
    struct timespec phase2_deadline = t_phase2_start;
    phase2_deadline.tv_sec += HANDSHAKE_TIMEOUT_MS / 1000;
    phase2_deadline.tv_nsec += (HANDSHAKE_TIMEOUT_MS % 1000) * 1000000L;
    if (phase2_deadline.tv_nsec >= 1000000000L) {
        phase2_deadline.tv_sec += 1;
        phase2_deadline.tv_nsec -= 1000000000L;
    }

    int handshakes_resolved = 0;   // ESTABLISHED + handshake_fail
    struct epoll_event events[MAX_EVENTS];

    while (handshakes_resolved < created) {
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        long ms_left = ms_until(&phase2_deadline, &t_now);
        if (ms_left <= 0) break;   /* window closed; stragglers = failed */

        int wait_ms = ms_left > 1000 ? 1000 : (int)ms_left;
        int n = epoll_wait(epfd, events, MAX_EVENTS, wait_ms);
        for (int i = 0; i < n; i++) {
            struct conn *c = (struct conn*)events[i].data.ptr;
            if (c->status != CONN_PENDING) continue;  /* shouldn't happen */

            /* Hard error during handshake. */
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                int err = 0; socklen_t sl = sizeof(err);
                getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &sl);
                c->err = err;
                c->status = CONN_DONE_ERR;
                handshake_fail++;
                if (!sample_handshake_errno) sample_handshake_errno = err;
                close(c->fd);
                handshakes_resolved++;
                continue;
            }

            if (events[i].events & EPOLLOUT) {
                int err = 0; socklen_t sl = sizeof(err);
                if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &sl) < 0 || err != 0) {
                    /* EPOLLOUT fired but SO_ERROR is non-zero — handshake
                     * actually failed (e.g. ECONNREFUSED, ETIMEDOUT). */
                    c->err = err;
                    c->status = CONN_DONE_ERR;
                    handshake_fail++;
                    if (!sample_handshake_errno) sample_handshake_errno = err;
                    close(c->fd);
                    handshakes_resolved++;
                    continue;
                }
                /* SO_ERROR == 0: handshake completed for real. */
                c->status = CONN_ESTABLISHED;
                established++;
                handshakes_resolved++;
            }
        }
    }

    /* Sweep stragglers: anything still PENDING after the window closed
     * is declared a handshake failure. No retry attempt. */
    int handshake_timeout_count = 0;
    for (int i = 0; i < created; i++) {
        if (conns[i].status == CONN_PENDING) {
            conns[i].status = CONN_DONE_ERR;
            conns[i].err = ETIMEDOUT;
            handshake_fail++;
            handshake_timeout_count++;
            close(conns[i].fd);
        }
    }

    struct timespec t_phase2_end;
    clock_gettime(CLOCK_MONOTONIC, &t_phase2_end);
    double phase2_elapsed = (t_phase2_end.tv_sec - t_phase2_start.tv_sec) +
                            (t_phase2_end.tv_nsec - t_phase2_start.tv_nsec) / 1e9;

    printf("Phase 2 (handshake, %dms window): established=%d handshake_fail=%d (of which %d hit the timeout) elapsed=%.4fs\n",
           HANDSHAKE_TIMEOUT_MS, established, handshake_fail, handshake_timeout_count, phase2_elapsed);
    if (handshake_fail) printf("  sample handshake errno: %d (%s)\n",
                               sample_handshake_errno, strerror(sample_handshake_errno));

    if (established == 0) {
        fprintf(stderr, "No connections established; nothing to time. Exiting.\n");
        free(conns);
        return 2;
    }

    /* Reconfigure epoll: only watch EPOLLIN on established connections.
     * We send up-front, then drain. No EPOLLOUT needed in Phase 3. */
    for (int i = 0; i < created; i++) {
        if (conns[i].status != CONN_ESTABLISHED) continue;
        struct epoll_event ev;
        ev.data.ptr = &conns[i];
        ev.events   = EPOLLIN | EPOLLET;
        epoll_ctl(epfd, EPOLL_CTL_MOD, conns[i].fd, &ev);
    }

    /* ============================================================
     * PHASE 3 — TIMED. send(req) on every established socket, then
     * drain responses. This is the only window contributing to the
     * reported throughput.
     * ============================================================ */

    const char *request =
        "GET /index.html HTTP/1.1\r\n"
        "Host: 10.10.1.1\r\n"
        "Connection: close\r\n\r\n";
    const size_t request_len = strlen(request);

    int done_ok    = 0;
    int done_err   = 0;
    int finished   = 0;   /* established connections that have left in-flight */
    int send_fail  = 0;   /* established but send() returned an error */
    int sample_send_errno = 0, sample_recv_errno = 0;

    struct timespec t_start, t_end, t_deadline;
    clock_gettime(CLOCK_MONOTONIC, &t_start);    /* <-- timer starts here */
    t_deadline = t_start;
    t_deadline.tv_sec += REQUEST_TIMEOUT_MS / 1000;

    /* Issue all sends inside the timed window. The request is small
     * (~70 bytes); the kernel send buffer accepts it immediately. */
    for (int i = 0; i < created; i++) {
        if (conns[i].status != CONN_ESTABLISHED) continue;
        ssize_t w = send(conns[i].fd, request, request_len, 0);
        if (w < 0) {
            if (!sample_send_errno) sample_send_errno = errno;
            conns[i].err = errno;
            conns[i].status = CONN_DONE_ERR;
            send_fail++;
            close(conns[i].fd);
            finished++;
        }
    }

    /* Drain responses. */
    while (finished < established) {
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        long ms_left = ms_until(&t_deadline, &t_now);
        if (ms_left <= 0) {
            fprintf(stderr,
                "Phase 3 timeout (%d ms) — %d still in flight; printing partial results\n",
                REQUEST_TIMEOUT_MS, established - finished);
            break;
        }

        int wait_ms = ms_left > 1000 ? 1000 : (int)ms_left;
        int n = epoll_wait(epfd, events, MAX_EVENTS, wait_ms);
        for (int i = 0; i < n; i++) {
            struct conn *c = (struct conn*)events[i].data.ptr;
            int fd = c->fd;
            if (c->status != CONN_ESTABLISHED) continue;

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                int err = 0; socklen_t sl = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl);
                c->err = err;
                c->status = CONN_DONE_ERR;
                done_err++;
                close(fd);
                finished++;
                continue;
            }

            if (events[i].events & EPOLLIN) {
                char buf[4096];
                while (1) {
                    int r = (int)recv(fd, buf, sizeof(buf), 0);
                    if (r == 0) {
                        /* Server FIN — clean completion. */
                        c->status = CONN_DONE_OK;
                        done_ok++;
                        close(fd);
                        finished++;
                        break;
                    } else if (r < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (!sample_recv_errno) sample_recv_errno = errno;
                        c->err = errno;
                        c->status = CONN_DONE_ERR;
                        done_err++;
                        close(fd);
                        finished++;
                        break;
                    }
                    /* r > 0: keep draining (EPOLLET requires this). */
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);    /* <-- timer stops here */
    double phase3_elapsed = (t_end.tv_sec - t_start.tv_sec) +
                            (t_end.tv_nsec - t_start.tv_nsec) / 1e9;

    int still_in_flight = established - finished;

    /* ============================================================
     * Report
     * ============================================================ */
    printf("\n==================== Results ====================\n");
    printf("Requested connections        : %d\n", NUM_CONN);
    printf("  socket() failures          : %d\n", socket_fail);
    printf("  bind() failures            : %d\n", bind_fail);
    printf("  connect() immediate fail   : %d\n", connect_immediate_fail);
    printf("Issued connect()s            : %d\n", created);
    printf("  handshake failed           : %d   (incl %d that hit the %dms timeout)\n",
           handshake_fail, handshake_timeout_count, HANDSHAKE_TIMEOUT_MS);
    printf("  ESTABLISHED                : %d   <-- denominator for throughput\n", established);
    printf("    send() failures          : %d\n", send_fail);
    printf("    completed cleanly        : %d\n", done_ok);
    printf("    completed with error     : %d\n", done_err);
    printf("    still in flight (timeout): %d\n", still_in_flight);
    if (send_fail) printf("    sample send() errno: %d (%s)\n",
                           sample_send_errno, strerror(sample_send_errno));
    if (sample_recv_errno) printf("    sample recv() errno: %d (%s)\n",
                                   sample_recv_errno, strerror(sample_recv_errno));
    printf("\n");
    printf("Phase-2 (handshake)  elapsed: %.4f s   (NOT included in throughput)\n", phase2_elapsed);
    printf("Phase-3 (send/recv)  elapsed: %.4f s   <-- timer for throughput\n",      phase3_elapsed);
    if (phase3_elapsed > 0) {
        printf("Request/response throughput  : %.2f conn/s   (= done_ok / phase-3 elapsed)\n",
               done_ok / phase3_elapsed);
    }

    /* Conservation sanity. */
    int phase1_sum = socket_fail + bind_fail + connect_immediate_fail;
    int phase12_sum = phase1_sum + handshake_fail + established;
    if (phase12_sum != NUM_CONN) {
        printf("WARN: Phase 1+2 counters sum to %d, expected %d\n", phase12_sum, NUM_CONN);
    }
    int phase3_sum = done_ok + done_err + send_fail + still_in_flight;
    if (phase3_sum != established) {
        printf("WARN: Phase 3 counters sum to %d, expected established=%d\n",
               phase3_sum, established);
    }
    printf("=================================================\n");

    free(conns);
    return 0;
}
