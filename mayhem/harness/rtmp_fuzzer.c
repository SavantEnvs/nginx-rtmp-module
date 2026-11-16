/*
 * nginx-rtmp-module fuzz targets driven through a real RTMP session (see fuzz_common.h).
 * One source, built once per mode (build.sh passes -DFZ_MODE=...):
 *
 *   FZ_MODE_SESSION  the input is everything an RTMP client sends to `listen 1935`: handshake,
 *                    chunk stream, AMF commands, audio/video/data messages (live, record, HLS,
 *                    DASH, codec parsing, vod/relay/notify applications by name).
 *   FZ_MODE_PROXY    the same, on `listen 1936 proxy_protocol`: the input starts with the PROXY
 *                    protocol header.
 *   FZ_MODE_MP4      the input is an .mp4 file a client plays from `play <dir>` (mp4 VOD reader).
 *   FZ_MODE_FLV      the input is an .flv file a client plays (flv VOD reader).
 *   FZ_MODE_RELAY    a client plays from an application with `pull rtmp://...`; the input is what
 *                    the remote RTMP server sends to nginx's relay (client-side handshake + replies).
 *   FZ_MODE_NOTIFY   a client publishes to an application with on_publish/on_play/... HTTP
 *                    callbacks; the input is the callback server's HTTP reply.
 */

#include "fuzz_common.h"

#define FZ_MODE_SESSION 1
#define FZ_MODE_PROXY   2
#define FZ_MODE_MP4     3
#define FZ_MODE_FLV     4
#define FZ_MODE_RELAY   5
#define FZ_MODE_NOTIFY  6

#ifndef FZ_MODE
#error "build with -DFZ_MODE=FZ_MODE_..."
#endif

static fz_buf_t fz_script;   /* the canned client conversation (file/relay/notify modes) */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fz_init();

#if (FZ_MODE == FZ_MODE_MP4 || FZ_MODE == FZ_MODE_FLV)
    {
        fz_buf_t m = { 0 };

        fz_rtmp_handshake(&fz_script);
        fz_rtmp_connect(&fz_script, "vod");
# if (FZ_MODE == FZ_MODE_MP4)
        fz_rtmp_stream_cmd(&fz_script, "play", "mp4:f.mp4", NULL);
# else
        fz_rtmp_stream_cmd(&fz_script, "play", "f", NULL);
# endif
        /* then seek to 1s into the file */
        fz_amf_str(&m, "seek");
        fz_amf_num(&m, 0);
        fz_amf_null(&m);
        fz_amf_num(&m, 1000);
        fz_rtmp_msg(&fz_script, 8, NGX_RTMP_MSG_AMF_CMD, 1, 0, &m);
        free(m.p);
    }
#elif (FZ_MODE == FZ_MODE_RELAY)
    fz_rtmp_handshake(&fz_script);
    fz_rtmp_connect(&fz_script, "relay");
    fz_rtmp_stream_cmd(&fz_script, "play", "s", NULL);
#elif (FZ_MODE == FZ_MODE_NOTIFY)
    fz_rtmp_handshake(&fz_script);
    fz_rtmp_connect(&fz_script, "notify");
    fz_rtmp_stream_cmd(&fz_script, "publish", "s", "live");
#endif
    return 0;
}

#if (FZ_MODE == FZ_MODE_MP4 || FZ_MODE == FZ_MODE_FLV)
static void
fz_write_vod(const uint8_t *data, size_t size)
{
    char  path[1024];
    FILE *f;

    snprintf(path, sizeof(path), "%s/vod/%s", fz_dir,
             FZ_MODE == FZ_MODE_MP4 ? "f.mp4" : "f.flv");
    f = fopen(path, "wb");
    if (f == NULL || (size && fwrite(data, 1, size, f) != size) || fclose(f) != 0) {
        fz_die("write vod file");
    }
}
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fz_run_t r;

    memset(&r, 0, sizeof(r));
    r.listen_port = FZ_PORT_RTMP;
    r.active_rounds = 24;

#if (FZ_MODE == FZ_MODE_SESSION || FZ_MODE == FZ_MODE_PROXY)
    r.client = data;
    r.client_len = size;
# if (FZ_MODE == FZ_MODE_PROXY)
    r.listen_port = FZ_PORT_PROXY;
# endif
#else
    r.client = fz_script.p;
    r.client_len = fz_script.len;
# if (FZ_MODE == FZ_MODE_MP4 || FZ_MODE == FZ_MODE_FLV)
    fz_write_vod(data, size);
    r.active_rounds = 40;
# else
    r.upstream = data;
    r.upstream_len = size;
# endif
#endif

    fz_run(&r);
    return 0;
}
