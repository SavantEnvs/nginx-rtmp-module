#!/usr/bin/env bash
#
# mayhem/test.sh — functional test of nginx-rtmp-module (upstream ships no automated suite).
#
# Runs the plain (non-sanitized) nginx + module that mayhem/build.sh built as a real RTMP/HTTP
# server, and drives it with mayhem/test/rtmp_check.py over loopback: a known publish session goes
# in, and the checks assert the module's actual output — handshake reply, AMF status codes, the
# codec parameters it parsed from the SPS/AudioSpecificConfig (stat XML), the recorded FLV's tags,
# the HLS playlist + MPEG-TS segments, and VOD playback of the recording. A server that does
# nothing fails every check.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

NGINX="$SRC/mayhem/out/nginx-rtmp-test"
if [ ! -x "$NGINX" ]; then
  echo "test.sh: $NGINX missing — run mayhem/build.sh first" >&2
  emit_ctrf "nginx-rtmp-check" 0 1
  exit 1
fi

out=$(python3 -I "$SRC/mayhem/test/rtmp_check.py" "$NGINX" "$SRC/mayhem/test" 2>&1)
echo "$out"
passed=$(grep -c '^PASS ' <<<"$out")
failed=$(grep -c '^FAIL ' <<<"$out")
# a checker that died before reporting counts as a failure
grep -q '^RESULT ' <<<"$out" || failed=$((failed + 1))
emit_ctrf "nginx-rtmp-check" "$passed" "$failed"
