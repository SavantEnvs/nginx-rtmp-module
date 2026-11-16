/*
 * ngx_rtmp_amf_read() — the module's AMF0 deserializer (ngx_rtmp_amf.h), the API every command,
 * metadata and relay/notify handler parses untrusted AMF through.
 *
 * Input layout: byte 0 picks the element table (the same tables the module's own handlers pass:
 * cmd_module's connect and play, codec_module's onMetaData, and NULL elts = "skip this many
 * values", as the module does for values it does not need); bytes 1-2 pick where the rest is split
 * into up to three ngx_buf_t chain links (an RTMP message arrives as a chain of chunk buffers, and
 * reads that straddle links are a separate code path). Each link's bytes live in their own heap
 * allocation, so ASan sees any read past a link's end.
 */

#include "fuzz_common.h"
#include "ngx_rtmp_amf.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fz_init();
    return 0;
}

static struct {
    double   trans, acodecs, vcodecs, object_encoding, start, duration, width, height, rate;
    double   vcodec_n, acodec_n;
    u_char   app[128], flashver[32], swf_url[128], tc_url[128], page_url[128], name[128];
    u_char   vcodec_s[32], acodec_s[32], profile[32], level[32];
    uint8_t  reset;
} v;

static ngx_rtmp_amf_elt_t connect_cmd[] = {
    { NGX_RTMP_AMF_STRING, ngx_string("app"), v.app, sizeof(v.app) },
    { NGX_RTMP_AMF_STRING, ngx_string("flashVer"), v.flashver, sizeof(v.flashver) },
    { NGX_RTMP_AMF_STRING, ngx_string("swfUrl"), v.swf_url, sizeof(v.swf_url) },
    { NGX_RTMP_AMF_STRING, ngx_string("tcUrl"), v.tc_url, sizeof(v.tc_url) },
    { NGX_RTMP_AMF_NUMBER, ngx_string("audioCodecs"), &v.acodecs, sizeof(v.acodecs) },
    { NGX_RTMP_AMF_NUMBER, ngx_string("videoCodecs"), &v.vcodecs, sizeof(v.vcodecs) },
    { NGX_RTMP_AMF_STRING, ngx_string("pageUrl"), v.page_url, sizeof(v.page_url) },
    { NGX_RTMP_AMF_NUMBER, ngx_string("objectEncoding"), &v.object_encoding, 0 },
};

static ngx_rtmp_amf_elt_t connect_elts[] = {
    { NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.trans, 0 },
    { NGX_RTMP_AMF_OBJECT, ngx_null_string, connect_cmd, sizeof(connect_cmd) },
};

static ngx_rtmp_amf_elt_t play_elts[] = {
    { NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.trans, 0 },
    { NGX_RTMP_AMF_NULL, ngx_null_string, NULL, 0 },
    { NGX_RTMP_AMF_STRING, ngx_null_string, v.name, sizeof(v.name) },
    { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.start, 0 },
    { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.duration, 0 },
    { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_BOOLEAN, ngx_null_string, &v.reset, 0 },
};

static ngx_rtmp_amf_elt_t meta_vcodec[] = {
    { NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.vcodec_n, 0 },
    { NGX_RTMP_AMF_STRING, ngx_null_string, v.vcodec_s, sizeof(v.vcodec_s) },
};

static ngx_rtmp_amf_elt_t meta_acodec[] = {
    { NGX_RTMP_AMF_NUMBER, ngx_null_string, &v.acodec_n, 0 },
    { NGX_RTMP_AMF_STRING, ngx_null_string, v.acodec_s, sizeof(v.acodec_s) },
};

static ngx_rtmp_amf_elt_t meta_inf[] = {
    { NGX_RTMP_AMF_NUMBER, ngx_string("width"), &v.width, 0 },
    { NGX_RTMP_AMF_NUMBER, ngx_string("height"), &v.height, 0 },
    { NGX_RTMP_AMF_NUMBER, ngx_string("duration"), &v.duration, 0 },
    { NGX_RTMP_AMF_NUMBER, ngx_string("framerate"), &v.rate, 0 },
    { NGX_RTMP_AMF_VARIANT, ngx_string("videocodecid"), meta_vcodec, sizeof(meta_vcodec) },
    { NGX_RTMP_AMF_VARIANT, ngx_string("audiocodecid"), meta_acodec, sizeof(meta_acodec) },
    { NGX_RTMP_AMF_STRING, ngx_string("profile"), v.profile, sizeof(v.profile) },
    { NGX_RTMP_AMF_STRING, ngx_string("level"), v.level, sizeof(v.level) },
};

static ngx_rtmp_amf_elt_t meta_elts[] = {
    { NGX_RTMP_AMF_STRING, ngx_null_string, NULL, 0 },
    { NGX_RTMP_AMF_OBJECT, ngx_null_string, meta_inf, sizeof(meta_inf) },
};

/* onMetaData as an ECMA (mixed) array, typeless first value, as data messages are read */
static ngx_rtmp_amf_elt_t meta_mixed_elts[] = {
    { NGX_RTMP_AMF_TYPELESS | NGX_RTMP_AMF_STRING, ngx_null_string, v.name, sizeof(v.name) },
    { NGX_RTMP_AMF_MIXED_ARRAY, ngx_null_string, meta_inf, sizeof(meta_inf) },
    { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_ARRAY, ngx_null_string, meta_inf, sizeof(meta_inf) },
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_rtmp_amf_ctx_t  act;
    ngx_chain_t         links[3];
    ngx_buf_t           bufs[3];
    u_char             *mem[3];
    size_t              cut[4], n;
    unsigned            sel;
    int                 i, nlinks;

    if (size < 3) {
        return 0;
    }
    sel = data[0];
    cut[0] = 0;
    cut[1] = (size_t) data[1] * (size - 3) / 255;
    cut[2] = (size_t) data[2] * (size - 3) / 255;
    if (cut[1] > cut[2]) {
        n = cut[1]; cut[1] = cut[2]; cut[2] = n;
    }
    cut[3] = size - 3;
    data += 3;

    ngx_memzero(&v, sizeof(v));
    ngx_memzero(bufs, sizeof(bufs));
    nlinks = 0;
    for (i = 0; i < 3; i++) {
        n = cut[i + 1] - cut[i];
        mem[i] = malloc(n ? n : 1);
        if (mem[i] == NULL) {
            abort();
        }
        memcpy(mem[i], data + cut[i], n);
        bufs[i].start = bufs[i].pos = mem[i];
        bufs[i].end = bufs[i].last = mem[i] + n;
        links[i].buf = &bufs[i];
        links[i].next = NULL;
        if (i > 0) {
            links[i - 1].next = &links[i];
        }
        nlinks++;
    }

    ngx_memzero(&act, sizeof(act));
    act.link = &links[0];
    act.log = fz_cycle->log;

    switch (sel % 5) {
    case 0:
        ngx_rtmp_amf_read(&act, connect_elts, sizeof(connect_elts) / sizeof(connect_elts[0]));
        break;
    case 1:
        ngx_rtmp_amf_read(&act, play_elts, sizeof(play_elts) / sizeof(play_elts[0]));
        break;
    case 2:
        ngx_rtmp_amf_read(&act, meta_elts, sizeof(meta_elts) / sizeof(meta_elts[0]));
        break;
    case 3:
        ngx_rtmp_amf_read(&act, meta_mixed_elts,
                          sizeof(meta_mixed_elts) / sizeof(meta_mixed_elts[0]));
        break;
    default:
        ngx_rtmp_amf_read(&act, NULL, 1 + (sel >> 4));
        break;
    }

    for (i = 0; i < nlinks; i++) {
        free(mem[i]);
    }
    return 0;
}
