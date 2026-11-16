#!/usr/bin/env bash
#
# mayhem/build.sh — build nginx-rtmp-module's fuzz harnesses and its functional-test server.
#
# The module has no build of its own: it is compiled into nginx (`./configure --add-module`). The
# pinned nginx source is cached in the image at /opt/toolchains/deps/nginx-$NGINX_VER/src
# (mayhem/Dockerfile); it is copied into mayhem/build/ (gitignored) and built out of the read-only
# deps tree, so this script runs offline and re-runs from scratch every time.
#
#   1) fuzz build: nginx + the module with $SANITIZER_FLAGS, SanitizerCoverage and DWARF 3; every
#      harness links all of nginx's objects (nginx.o's main() renamed away) with libFuzzer, and once
#      more with $STANDALONE_FUZZ_MAIN for a run-once reproducer.
#   2) test build: a plain nginx + module (normal flags) that mayhem/test.sh runs as a real server.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${NGINX_VER:=1.24.0}"
: "${NGINX_SRC:=/opt/toolchains/deps/nginx-${NGINX_VER}/src}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
MOD="$SRC"                       # the module (repo root)
B="$SRC/mayhem/build"            # gitignored (mayhem/.gitignore)
OUT="$SRC/mayhem/out"            # gitignored; the Mayhemfiles run /mayhem/mayhem/out/<name>

[ -f "$NGINX_SRC/configure" ] || { echo "nginx source missing at $NGINX_SRC" >&2; exit 1; }

# no PCRE/zlib in the module's code paths; the HTTP part is kept for the stat/control modules
NGX_CONF_ARGS=(--add-module="$MOD" --without-http_rewrite_module --without-http_gzip_module
               --with-poll_module)

fresh_nginx() {  # $1 = build dir: a clean, writable copy of the pinned nginx source
    rm -rf "$1"
    mkdir -p "$1"
    cp -R "$NGINX_SRC/." "$1/"
    chmod -R u+w "$1"
}

# ---- 1) fuzz build --------------------------------------------------------------------------
FZ="$B/fuzz"
fresh_nginx "$FZ"
# fuzzer-no-link: SanitizerCoverage on nginx + the module, the libFuzzer runtime only in harnesses.
# Two UBSan checks are relaxed, because they fire on benign patterns on (nearly) every input:
#  - alignment: the handshake reads the C1/S1 version word as *(uint32_t *)(buf + 5) on every
#    connection (ngx_rtmp_handshake.c:304); unaligned loads are fine on x86.
#  - nonnull-attribute: nginx core's ngx_cpymem() is memcpy(dst, NULL, 0) for every empty ngx_str_t
#    printed with %V (every `play`, every DASH playlist write); a NULL with a non-zero length still
#    faults under ASan.
# ASan and every other UBSan check stay on and halting.
NO_ALIGN="-fno-sanitize=alignment,nonnull-attribute"
# NGX_DEBUG_PALLOC: ngx_palloc()/ngx_pnalloc() normally carve small requests out of the pool's shared
# block, with no redzone between them, so ASan can't see an overflow of a pool buffer (the RTMP chunk
# buffers, AMF/codec/metadata payloads all live in s->in_pool). With it, every pool allocation is its
# own malloc() (as in OSS-Fuzz's nginx build). Fuzz build only.
PALLOC="-DNGX_DEBUG_PALLOC=1"
FZ_CFLAGS="$SANITIZER_FLAGS $NO_ALIGN $PALLOC -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -Wno-error"
(
    cd "$FZ"
    ./configure --with-cc="$CC" --with-cc-opt="$FZ_CFLAGS" \
        --with-ld-opt="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" "${NGX_CONF_ARGS[@]}" >configure.log 2>&1 \
        || { tail -40 configure.log >&2; exit 1; }
    make -f objs/Makefile -j"$MAYHEM_JOBS" objs/nginx >make.log 2>&1 || { tail -60 make.log >&2; exit 1; }
)

# the libraries nginx links (from its own link line), and every object except main's
NGX_LIBS=$(sed -n '/-o objs\/nginx/,/^$/p' "$FZ/objs/Makefile" | grep -oE '(^|[[:space:]])-l[^[:space:]\\]+' | tr '\n' ' ')
mapfile -t NGX_OBJS < <(cd "$FZ" && find objs -name '*.o' ! -path 'objs/src/core/nginx.o' | sort)
llvm-objcopy --redefine-sym main=ngx_orig_main "$FZ/objs/src/core/nginx.o" "$FZ/nginx_nomain.o"
NGX_INCS=(-I"$FZ/objs" -I"$FZ/src/core" -I"$FZ/src/event" -I"$FZ/src/event/modules"
          -I"$FZ/src/os/unix" -I"$FZ/src/http" -I"$FZ/src/http/modules" -I"$MOD")

mkdir -p "$OUT"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

WRAP="-Wl,--wrap=bind,--wrap=listen"

link_harness() {  # $1 = target name, $2 = harness source, $3.. = extra cflags
    local name="$1" src="$2"; shift 2
    $CC $SANITIZER_FLAGS $NO_ALIGN $PALLOC -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 "$@" "${NGX_INCS[@]}" \
        -c "$src" -o "$B/$name.o"
    ( cd "$FZ" && $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $WRAP \
        "$B/$name.o" "${NGX_OBJS[@]}" nginx_nomain.o "$B/lsan_off.o" $NGX_LIBS -o "$OUT/$name" )
    ( cd "$FZ" && $CC $SANITIZER_FLAGS $DEBUG_FLAGS $WRAP \
        "$B/$name.o" "${NGX_OBJS[@]}" nginx_nomain.o "$B/lsan_off.o" "$B/standalone_main.o" \
        $NGX_LIBS -o "$OUT/$name-standalone" )
}

H="$SRC/mayhem/harness"
link_harness rtmp_session_fuzzer        "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_SESSION
link_harness rtmp_proxy_protocol_fuzzer "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_PROXY
link_harness rtmp_mp4_vod_fuzzer        "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_MP4
link_harness rtmp_flv_vod_fuzzer        "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_FLV
link_harness rtmp_relay_fuzzer          "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_RELAY
link_harness rtmp_notify_fuzzer         "$H/rtmp_fuzzer.c" -DFZ_MODE=FZ_MODE_NOTIFY
link_harness rtmp_amf_fuzzer            "$H/rtmp_amf_fuzzer.c"

# ---- 2) test build: plain nginx + module, normal flags --------------------------------------
TB="$B/test"
fresh_nginx "$TB"
(
    cd "$TB"
    env -u CFLAGS -u LDFLAGS ./configure --with-cc="$CC" --with-cc-opt="-O2 -Wno-error $COVERAGE_FLAGS" \
        --with-ld-opt="$COVERAGE_FLAGS" "${NGX_CONF_ARGS[@]}" >configure.log 2>&1 \
        || { tail -40 configure.log >&2; exit 1; }
    make -f objs/Makefile -j"$MAYHEM_JOBS" objs/nginx >make.log 2>&1 || { tail -60 make.log >&2; exit 1; }
)
cp -f "$TB/objs/nginx" "$OUT/nginx-rtmp-test"

echo "build.sh: done"
ls -l "$OUT"
