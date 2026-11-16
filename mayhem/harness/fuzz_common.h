/*
 * Shared scaffolding for the nginx-rtmp-module fuzz harnesses.
 *
 * The module only exists inside nginx, so each harness links the whole nginx build (every object
 * except nginx.o's main, which build.sh renames to ngx_orig_main) and boots one nginx cycle from a
 * generated nginx.conf in LLVMFuzzerInitialize, the way OSS-Fuzz's nginx http_request_fuzzer does.
 *
 * Per input, a real loopback TCP connection is handed to the RTMP listener's own handler
 * (ngx_rtmp_init_connection, exactly what ngx_event_accept would call), and nginx's real poll event
 * module drives it: the harness writes the fuzz bytes into the peer socket, drains what nginx sends
 * back, and runs nginx's event loop (ngx_process_events with a zero timeout, posted events, timers).
 * Real sockets matter: the PROXY protocol reader peeks the socket with recv(MSG_PEEK) directly.
 *
 * Outgoing connections the module opens (relay pull/push, notify/netcall HTTP callbacks) go to a
 * loopback listener owned by the harness; every connection accepted there receives the "upstream"
 * bytes of the run, so the remote server's replies can be the fuzz input.
 *
 * Time is virtual: ngx_current_msec only moves when the harness advances it, so timers (ping,
 * play/send scheduling, timeouts, HLS/DASH fragment boundaries) fire deterministically, independent
 * of host speed. There is no wall-clock timeout anywhere: Mayhem owns timeouts.
 *
 * State kept across inputs, on purpose: the nginx cycle and its configuration (read-only after
 * init), the harness's listening socket, and the scratch directory. Each run ends only after the
 * session (and any relay/netcall connection it opened) is closed, which releases every per-session
 * structure (the live stream table entries are returned to the app's free list); the files the
 * record/HLS/DASH modules wrote are deleted after each run, so the next input starts from the
 * same empty directories.
 *
 * bind() and listen() are wrapped (link-time --wrap, mocking only the OS socket layer, as OSS-Fuzz's
 * nginx build does) so nginx's configured listeners never bind a real port: concurrent fuzzer
 * instances cannot collide, and no connection ever arrives through them.
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_rtmp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int __real_bind(int s, const struct sockaddr *a, socklen_t l);
int __real_listen(int s, int backlog);

int
__wrap_bind(int s, const struct sockaddr *a, socklen_t l)
{
    (void) s; (void) a; (void) l;
    return 0;
}

int
__wrap_listen(int s, int backlog)
{
    (void) s; (void) backlog;
    return 0;
}

#define FZ_PORT_RTMP   1935
#define FZ_PORT_PROXY  1936

/* The configuration every harness boots. @DIR@ is the scratch dir, @PORT@ the harness's own
 * loopback listener (relay upstream / HTTP callback server), @LOG@/@LEVEL@ the error log. */
static const char fz_conf_tmpl[] =
    "daemon off;\n"
    "master_process off;\n"
    "worker_processes 1;\n"
    "error_log @LOG@ @LEVEL@;\n"
    "pid @DIR@/logs/nginx.pid;\n"
    "lock_file @DIR@/logs/nginx.lock;\n"
    "events { use poll; worker_connections 128; }\n"
    "rtmp {\n"
    "  server {\n"
    "    listen 127.0.0.1:1935;\n"
    "    ping 30s;\n"
    "    ping_timeout 10s;\n"
    "    max_message 1M;\n"
    "    application live {\n"
    "      live on;\n"
    "      meta copy;\n"
    "      record all;\n"
    "      record_path @DIR@/rec;\n"
    "      hls on;\n"
    "      hls_path @DIR@/hls;\n"
    "      hls_fragment 1s;\n"
    "      hls_playlist_length 3s;\n"
    "      dash on;\n"
    "      dash_path @DIR@/dash;\n"
    "      dash_fragment 1s;\n"
    "      dash_playlist_length 3s;\n"
    "    }\n"
    "    application live2 {\n"
    "      live on;\n"
    "      interleave on;\n"
    "      wait_key on;\n"
    "      wait_video on;\n"
    "      sync 10ms;\n"
    "      drop_idle_publisher 5s;\n"
    "      allow publish 127.0.0.1;\n"
    "      deny play 10.0.0.0/8;\n"
    "      record keyframes manual;\n"
    "      record_path @DIR@/rec;\n"
    "      record_unique on;\n"
    "      record_max_frames 8;\n"
    "      record_interval 2s;\n"
    "      recorder audio { record audio; record_path @DIR@/rec; record_suffix -audio.flv; }\n"
    "      hls on;\n"
    "      hls_path @DIR@/hls2;\n"
    "      hls_nested on;\n"
    "      hls_fragment 500ms;\n"
    "      hls_fragment_naming timestamp;\n"
    "      hls_fragment_slicing aligned;\n"
    "      hls_type event;\n"
    "      hls_keys on;\n"
    "      hls_key_path @DIR@/keys;\n"
    "      hls_fragments_per_key 2;\n"
    "      hls_variant _low BANDWIDTH=160000;\n"
    "      hls_variant _hi BANDWIDTH=640000;\n"
    "      dash on;\n"
    "      dash_path @DIR@/dash2;\n"
    "      dash_nested on;\n"
    "      dash_fragment 500ms;\n"
    "    }\n"
    "    application vod {\n"
    "      play @DIR@/vod;\n"
    "    }\n"
    "    application relay {\n"
    "      live on;\n"
    "      pull rtmp://127.0.0.1:@PORT@/up;\n"
    "    }\n"
    "    application notify {\n"
    "      live on;\n"
    "      on_publish http://127.0.0.1:@PORT@/publish;\n"
    "      on_play http://127.0.0.1:@PORT@/play;\n"
    "      on_publish_done http://127.0.0.1:@PORT@/publish_done;\n"
    "      on_update http://127.0.0.1:@PORT@/update;\n"
    "      notify_update_timeout 2s;\n"
    "      notify_method get;\n"
    "    }\n"
    "  }\n"
    "  server {\n"
    "    listen 127.0.0.1:1936 proxy_protocol;\n"
    "    application live {\n"
    "      live on;\n"
    "      record all;\n"
    "      record_path @DIR@/rec;\n"
    "    }\n"
    "  }\n"
    "}\n";

/* Directories (under the scratch dir) the configuration writes into; emptied after every run. */
static const char *fz_scratch_dirs[] = {
    "rec", "hls", "hls2", "dash", "dash2", "keys", "vod", NULL
};

static ngx_cycle_t  *fz_cycle;
static char          fz_dir[512];
static int           fz_lfd = -1;
static int           fz_lport;
static int           fz_check;           /* FZ_CHECK=1: report state left over by a run */

static void
fz_die(const char *what)
{
    fprintf(stderr, "nginx-rtmp fuzz harness init failed: %s (errno %d)\n", what, errno);
    abort();
}

static void
fz_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        fz_die("fcntl");
    }
}

static char *
fz_subst(const char *tmpl)
{
    char        port[16], *out, *o;
    const char *log, *level, *p;
    size_t      cap;

    log = getenv("FZ_NGX_LOG") ? "stderr" : "/dev/null";
    level = getenv("FZ_NGX_LOG") ? getenv("FZ_NGX_LOG") : "emerg";
    if (*level == '\0' || strcmp(level, "1") == 0) {
        level = "info";
    }
    snprintf(port, sizeof(port), "%d", fz_lport);

    cap = strlen(tmpl) * 2 + 64 * strlen(fz_dir) + 256;
    out = o = malloc(cap);
    if (out == NULL) {
        fz_die("malloc");
    }

    for (p = tmpl; *p; ) {
        const char *rep = NULL;
        size_t      skip = 0;

        if (strncmp(p, "@DIR@", 5) == 0) { rep = fz_dir; skip = 5; }
        else if (strncmp(p, "@PORT@", 6) == 0) { rep = port; skip = 6; }
        else if (strncmp(p, "@LOG@", 5) == 0) { rep = log; skip = 5; }
        else if (strncmp(p, "@LEVEL@", 7) == 0) { rep = level; skip = 7; }

        if (rep) {
            o = stpcpy(o, rep);
            p += skip;
        } else {
            *o++ = *p++;
        }
    }
    *o = '\0';
    return out;
}

static void
fz_mkdir(const char *sub)
{
    char path[1024];

    snprintf(path, sizeof(path), "%s/%s", fz_dir, sub);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        fz_die("mkdir");
    }
}

static int
fz_rm_cb(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void) st; (void) flag;
    if (ftw->level > 0) {
        remove(path);
    }
    return 0;
}

/* Empty the directories the modules write into (keeps the directories themselves). */
static void
fz_clean_scratch(void)
{
    char path[1024];
    int  i;

    for (i = 0; fz_scratch_dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", fz_dir, fz_scratch_dirs[i]);
        nftw(path, fz_rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    }
}

static void
fz_init(void)
{
    static ngx_cycle_t   init_cycle;
    static char         *argv[] = { "nginx", NULL };
    static char          prefix[600], conf_file[600];
    struct sockaddr_in   sin;
    socklen_t            slen;
    ngx_log_t           *log;
    ngx_cycle_t         *cycle;
    ngx_listening_t     *ls;
    ngx_uint_t           i;
    const char          *tmp;
    char                *conf;
    FILE                *f;
    int                  one = 1;

    signal(SIGPIPE, SIG_IGN);
    fz_check = getenv("FZ_CHECK") != NULL;

    tmp = getenv("TMPDIR");
    if (tmp == NULL || *tmp == '\0') {
        tmp = "/tmp";
    }
    snprintf(fz_dir, sizeof(fz_dir), "%s/ngx-rtmp-fuzz-XXXXXX", tmp);
    if (mkdtemp(fz_dir) == NULL) {
        fz_die("mkdtemp");
    }
    fz_mkdir("logs");
    for (i = 0; fz_scratch_dirs[i]; i++) {
        fz_mkdir(fz_scratch_dirs[i]);
    }

    /* the harness's own loopback listener: client connections + module's outgoing connections */
    fz_lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (fz_lfd < 0) {
        fz_die("socket");
    }
    setsockopt(fz_lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (__real_bind(fz_lfd, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || __real_listen(fz_lfd, 128) != 0)
    {
        fz_die("bind/listen loopback");
    }
    slen = sizeof(sin);
    if (getsockname(fz_lfd, (struct sockaddr *) &sin, &slen) != 0) {
        fz_die("getsockname");
    }
    fz_lport = ntohs(sin.sin_port);
    fz_set_nonblock(fz_lfd);

    conf = fz_subst(fz_conf_tmpl);
    snprintf(conf_file, sizeof(conf_file), "%s/nginx.conf", fz_dir);
    f = fopen(conf_file, "w");
    if (f == NULL || fputs(conf, f) < 0 || fclose(f) != 0) {
        fz_die("write nginx.conf");
    }
    free(conf);
    snprintf(prefix, sizeof(prefix), "%s/", fz_dir);

    /* what nginx's main() does up to ngx_init_cycle(), minus option parsing / daemonizing */
    ngx_debug_init();
    if (ngx_strerror_init() != NGX_OK) {
        fz_die("ngx_strerror_init");
    }
    ngx_max_sockets = -1;
    ngx_time_init();
    ngx_pid = ngx_getpid();
    ngx_parent = ngx_getppid();

    log = ngx_log_init((u_char *) prefix, (u_char *) "/dev/null");
    if (log == NULL) {
        fz_die("ngx_log_init");
    }
#if (NGX_OPENSSL)
    ngx_ssl_init(log);
#endif

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;
    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        fz_die("ngx_create_pool");
    }

    ngx_argc = 1;
    ngx_argv = argv;
    ngx_os_argv = argv;

    init_cycle.prefix.data = (u_char *) prefix;
    init_cycle.prefix.len = strlen(prefix);
    init_cycle.conf_prefix = init_cycle.prefix;
    init_cycle.conf_file.data = (u_char *) conf_file;
    init_cycle.conf_file.len = strlen(conf_file);
    ngx_str_set(&init_cycle.conf_param, "");
    ngx_str_set(&init_cycle.error_log, "/dev/null");

    if (ngx_os_init(log) != NGX_OK) {
        fz_die("ngx_os_init");
    }
    if (ngx_crc32_table_init() != NGX_OK) {
        fz_die("ngx_crc32_table_init");
    }
    ngx_slab_sizes_init();
    if (ngx_preinit_modules() != NGX_OK) {
        fz_die("ngx_preinit_modules");
    }

    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        fz_die("ngx_init_cycle (re-run with FZ_NGX_LOG=1 to see why)");
    }
    ngx_cycle = cycle;
    fz_cycle = cycle;

    /* what ngx_single_process_cycle() does before its event loop */
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process
            && cycle->modules[i]->init_process(cycle) == NGX_ERROR)
        {
            fz_die("init_process");
        }
    }

    /* the configured listeners are never bound (see __wrap_bind): stop polling them */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].connection && ls[i].connection->read->active) {
            ngx_del_event(ls[i].connection->read, NGX_READ_EVENT, 0);
        }
    }
}

static ngx_listening_t *
fz_find_listening(in_port_t port)
{
    ngx_listening_t  *ls;
    ngx_uint_t        i;

    ls = fz_cycle->listening.elts;
    for (i = 0; i < fz_cycle->listening.nelts; i++) {
        if (ls[i].sockaddr->sa_family == AF_INET
            && ntohs(((struct sockaddr_in *) ls[i].sockaddr)->sin_port) == port)
        {
            return &ls[i];
        }
    }
    fz_die("no listener on the expected port");
    return NULL;
}

/* ---- per-run driver ------------------------------------------------------------------------- */

#define FZ_MAX_PEERS  16

typedef struct {
    int           fd;
    const u_char *data;
    size_t        len, off;
    int           wr_closed, rd_eof;
    size_t        rx;            /* bytes nginx sent to this peer */
    int           server;        /* an outgoing connection's far end: speaks second */
} fz_peer_t;

typedef struct {
    const u_char *client;        /* bytes the RTMP client sends */
    size_t        client_len;
    const u_char *upstream;      /* bytes every outgoing (relay / HTTP callback) connection gets */
    size_t        upstream_len;
    in_port_t     listen_port;   /* FZ_PORT_RTMP or FZ_PORT_PROXY */
    int           active_rounds; /* event-loop rounds (FZ_STEP_MS apart) before the client's EOF */
} fz_run_t;

#define FZ_STEP_MS  250

static fz_peer_t  fz_peers[FZ_MAX_PEERS + 1];
static int        fz_npeers;
static int        fz_main_closed;

static void
fz_peer_eof(fz_peer_t *p)
{
    if (p->fd >= 0 && !p->wr_closed) {
        shutdown(p->fd, SHUT_WR);
        p->wr_closed = 1;
    }
}

static void
fz_peer_io(fz_peer_t *p)
{
    u_char   buf[16384];
    ssize_t  n;

    if (p->fd < 0) {
        return;
    }
    while (!p->rd_eof) {
        n = recv(p->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            p->rx += n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            break;
        }
        p->rd_eof = 1;
    }
    /* a server (relay upstream, HTTP callback server) only answers once nginx has spoken */
    if (p->server && p->rx == 0) {
        return;
    }
    while (!p->wr_closed && p->off < p->len) {
        n = send(p->fd, p->data + p->off, p->len - p->off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            p->off += n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            break;
        }
        p->wr_closed = 1;
    }
}

static void
fz_accept_upstreams(const fz_run_t *r, int eof)
{
    int fd;

    for ( ;; ) {
        fd = accept(fz_lfd, NULL, NULL);
        if (fd < 0) {
            return;
        }
        if (fz_npeers > FZ_MAX_PEERS) {
            close(fd);
            continue;
        }
        fz_set_nonblock(fd);
        memset(&fz_peers[fz_npeers], 0, sizeof(fz_peer_t));
        fz_peers[fz_npeers].fd = fd;
        fz_peers[fz_npeers].data = r->upstream;
        fz_peers[fz_npeers].len = r->upstream_len;
        fz_peers[fz_npeers].server = 1;
        if (eof) {
            fz_peer_io(&fz_peers[fz_npeers]);
            fz_peer_eof(&fz_peers[fz_npeers]);
        }
        fz_npeers++;
    }
}

/* one pass of nginx's worker loop, with a zero poll timeout and virtual time */
static void
fz_step(const fz_run_t *r, int up_eof, ngx_msec_t advance)
{
    int i;

    fz_accept_upstreams(r, up_eof);
    for (i = 0; i < fz_npeers; i++) {
        fz_peer_io(&fz_peers[i]);
        if (up_eof && i > 0 && fz_peers[i].off >= fz_peers[i].len) {
            fz_peer_eof(&fz_peers[i]);
        }
    }

    (void) ngx_process_events(fz_cycle, 0, 0);
    ngx_event_process_posted(fz_cycle, &ngx_posted_events);
    if (!ngx_queue_empty(&ngx_posted_next_events)) {
        ngx_event_move_posted_next(fz_cycle);
    }

    ngx_current_msec += advance;
    ngx_event_expire_timers();
    ngx_event_process_posted(fz_cycle, &ngx_posted_events);
}

static void
fz_main_pool_cleanup(void *data)
{
    (void) data;
    fz_main_closed = 1;
}

/* what ngx_event_accept() does for a new connection on listener `ls` */
static ngx_connection_t *
fz_accept_connection(int fd, ngx_listening_t *ls, struct sockaddr *sa, socklen_t salen)
{
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = ngx_get_connection(fd, fz_cycle->log);
    if (c == NULL) {
        return NULL;
    }
    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(ls->pool_size, fz_cycle->log);
    c->sockaddr = ngx_palloc(c->pool, salen);
    c->log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (c->sockaddr == NULL || c->log == NULL || cln == NULL) {
        fz_die("connection pool");
    }
    cln->handler = fz_main_pool_cleanup;

    ngx_memcpy(c->sockaddr, sa, salen);
    c->socklen = salen;
    *c->log = ls->log;
    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;
    c->listening = ls;
    c->read->log = c->log;
    c->write->log = c->log;
    c->write->ready = 1;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->start_time = ngx_current_msec;

    c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
    if (c->addr_text.data == NULL) {
        fz_die("addr_text");
    }
    c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen, c->addr_text.data,
                                     ls->addr_text_max_len, 0);
    return c;
}

static void
fz_run(const fz_run_t *r)
{
    struct sockaddr_storage  pa;
    struct sockaddr_in       sin;
    socklen_t                plen;
    ngx_listening_t         *ls;
    ngx_connection_t        *c;
    int                      cfd, sfd, i, round;
    ngx_uint_t               free_before;

    ls = fz_find_listening(r->listen_port);
    free_before = fz_cycle->free_connection_n;

    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) {
        fz_die("client socket");
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(fz_lport);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(cfd, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        fz_die("client connect");
    }
    plen = sizeof(pa);
    sfd = accept(fz_lfd, (struct sockaddr *) &pa, &plen);
    if (sfd < 0) {
        fz_die("accept client");
    }
    fz_set_nonblock(cfd);
    fz_set_nonblock(sfd);

    fz_npeers = 1;
    memset(&fz_peers[0], 0, sizeof(fz_peer_t));
    fz_peers[0].fd = cfd;
    fz_peers[0].data = r->client;
    fz_peers[0].len = r->client_len;

    fz_main_closed = 0;
    c = fz_accept_connection(sfd, ls, (struct sockaddr *) &pa, plen);
    if (c == NULL) {
        close(sfd);
        close(cfd);
        return;
    }
    ls->handler(c);
    ngx_event_process_posted(fz_cycle, &ngx_posted_events);

    /* the conversation: client (and upstream) bytes flow, timers fire every FZ_STEP_MS */
    for (round = 0; round < r->active_rounds && !fz_main_closed; round++) {
        fz_step(r, 0, FZ_STEP_MS);
    }
    /* a long idle stretch: ping, ping timeout, drop_idle_publisher, session timeouts */
    for (round = 0; round < 3 && !fz_main_closed; round++) {
        fz_step(r, 0, 20000);
    }

    /* the client (and every upstream) closes its side */
    fz_peer_eof(&fz_peers[0]);
    for (i = 1; i < fz_npeers; i++) {
        fz_peer_eof(&fz_peers[i]);
    }
    for (round = 0; round < 16 && !fz_main_closed; round++) {
        fz_step(r, 1, FZ_STEP_MS);
    }

    for (i = 0; i < fz_npeers; i++) {
        if (fz_check) {
            fprintf(stderr, "FZ_CHECK: peer %d: sent %zu/%zu bytes, received %zu\n",
                    i, fz_peers[i].off, fz_peers[i].len, fz_peers[i].rx);
        }
        if (fz_peers[i].fd >= 0) {
            close(fz_peers[i].fd);
            fz_peers[i].fd = -1;
        }
    }
    for (round = 0; round < 8; round++) {
        fz_step(r, 1, 1000);
    }

    if (!fz_main_closed) {
        /* nothing should keep a session open once its peer is gone; close it so the next input
         * starts clean */
        if (fz_check) {
            fprintf(stderr, "FZ_CHECK: session still open after the peer closed\n");
        }
        ngx_rtmp_finalize_session(c->data);
        for (round = 0; round < 4; round++) {
            fz_step(r, 1, 1000);
        }
    }
    /* connections the module opened (relay, netcall) that the harness already closed */
    for (round = 0; round < 4 && fz_cycle->free_connection_n != free_before; round++) {
        fz_step(r, 1, 5000);
    }

    if (fz_check) {
        if (fz_cycle->free_connection_n != free_before) {
            fprintf(stderr, "FZ_CHECK: %d connection(s) left open\n",
                    (int) (free_before - fz_cycle->free_connection_n));
        }
        if (ngx_event_timer_rbtree.root != ngx_event_timer_rbtree.sentinel) {
            fprintf(stderr, "FZ_CHECK: timers left armed\n");
        }
        if (!ngx_queue_empty(&ngx_posted_events)) {
            fprintf(stderr, "FZ_CHECK: posted events left\n");
        }
    }

    fz_clean_scratch();
}

/* ---- canned RTMP client conversations (for targets whose fuzz input is not the client) -------- */

typedef struct {
    u_char  *p;
    size_t   len, cap;
} fz_buf_t;

static void
fz_put(fz_buf_t *b, const void *d, size_t n)
{
    if (b->len + n > b->cap) {
        b->cap = (b->len + n) * 2 + 4096;
        b->p = realloc(b->p, b->cap);
        if (b->p == NULL) {
            fz_die("realloc");
        }
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

static void fz_u8(fz_buf_t *b, unsigned v) { u_char c = (u_char) v; fz_put(b, &c, 1); }
static void fz_be16(fz_buf_t *b, unsigned v) { fz_u8(b, v >> 8); fz_u8(b, v); }
static void fz_be24(fz_buf_t *b, unsigned v) { fz_u8(b, v >> 16); fz_be16(b, v); }

static void
fz_amf_num(fz_buf_t *b, double d)
{
    uint64_t u;
    int      i;

    memcpy(&u, &d, 8);
    fz_u8(b, NGX_RTMP_AMF_NUMBER);
    for (i = 7; i >= 0; i--) {
        fz_u8(b, (unsigned) (u >> (i * 8)));
    }
}

static void
fz_amf_str(fz_buf_t *b, const char *s)
{
    fz_u8(b, NGX_RTMP_AMF_STRING);
    fz_be16(b, strlen(s));
    fz_put(b, s, strlen(s));
}

static void
fz_amf_key(fz_buf_t *b, const char *s)
{
    fz_be16(b, strlen(s));
    fz_put(b, s, strlen(s));
}

static void fz_amf_null(fz_buf_t *b) { fz_u8(b, NGX_RTMP_AMF_NULL); }
static void fz_amf_obj_end(fz_buf_t *b) { fz_be16(b, 0); fz_u8(b, NGX_RTMP_AMF_END); }

/* one RTMP message, split into 128-byte chunks (the default chunk size) */
static void
fz_rtmp_msg(fz_buf_t *out, unsigned csid, unsigned type, uint32_t msid, uint32_t ts,
            const fz_buf_t *payload)
{
    size_t off, n;

    fz_u8(out, csid);                   /* fmt 0 */
    fz_be24(out, ts);
    fz_be24(out, payload->len);
    fz_u8(out, type);
    fz_u8(out, msid); fz_u8(out, msid >> 8); fz_u8(out, msid >> 16); fz_u8(out, msid >> 24);
    for (off = 0; off < payload->len; off += n) {
        if (off) {
            fz_u8(out, 0xc0 | csid);    /* fmt 3 continuation */
        }
        n = payload->len - off > 128 ? 128 : payload->len - off;
        fz_put(out, payload->p + off, n);
    }
}

/* C0 + C1 (version 0: the plain, digest-less handshake) + C2 */
static void
fz_rtmp_handshake(fz_buf_t *out)
{
    static u_char zero[1536];

    fz_u8(out, 3);
    fz_put(out, zero, sizeof(zero));
    fz_put(out, zero, sizeof(zero));
}

static void
fz_rtmp_connect(fz_buf_t *out, const char *app)
{
    fz_buf_t  m = { 0 };
    char      tc[128];

    snprintf(tc, sizeof(tc), "rtmp://127.0.0.1/%s", app);
    fz_amf_str(&m, "connect");
    fz_amf_num(&m, 1);
    fz_u8(&m, NGX_RTMP_AMF_OBJECT);
    fz_amf_key(&m, "app"); fz_amf_str(&m, app);
    fz_amf_key(&m, "flashVer"); fz_amf_str(&m, "LNX 9,0,124,2");
    fz_amf_key(&m, "tcUrl"); fz_amf_str(&m, tc);
    fz_amf_key(&m, "objectEncoding"); fz_amf_num(&m, 0);
    fz_amf_obj_end(&m);
    fz_rtmp_msg(out, 3, NGX_RTMP_MSG_AMF_CMD, 0, 0, &m);
    free(m.p);

    m.p = NULL; m.len = m.cap = 0;
    fz_amf_str(&m, "createStream");
    fz_amf_num(&m, 2);
    fz_amf_null(&m);
    fz_rtmp_msg(out, 3, NGX_RTMP_MSG_AMF_CMD, 0, 0, &m);
    free(m.p);
}

/* "play"/"publish" on message stream 1 (the first createStream result) */
static void
fz_rtmp_stream_cmd(fz_buf_t *out, const char *cmd, const char *name, const char *extra)
{
    fz_buf_t m = { 0 };

    fz_amf_str(&m, cmd);
    fz_amf_num(&m, 0);
    fz_amf_null(&m);
    fz_amf_str(&m, name);
    if (extra) {
        fz_amf_str(&m, extra);
    }
    fz_rtmp_msg(out, 8, NGX_RTMP_MSG_AMF_CMD, 1, 0, &m);
    free(m.p);
}

#endif /* FUZZ_COMMON_H */
