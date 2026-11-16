#!/usr/bin/env python3
"""Functional test of nginx-rtmp-module against a real nginx built with it (mayhem/build.sh).

Starts the server, publishes a known stream (mayhem/test/publish.bin: handshake, connect,
createStream, publish "s" to app "live", onMetaData, an H.264 320x240 Baseline SPS/PPS, an AAC-LC
44.1 kHz stereo config, 30 video + 30 audio frames), and asserts what the module must produce:
the handshake reply, the AMF status replies, the codec details it parsed (via the stat module's
XML), the recorded FLV, the HLS playlist/segments, and VOD playback of the recording.

  rtmp_check.py <nginx binary> <fixtures dir>
Prints one "PASS name" / "FAIL name: why" line per check, and a final "RESULT passed failed".
"""
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

NGINX, FIX = sys.argv[1], sys.argv[2]
results = []


def check(name, cond, why=""):
    results.append(bool(cond))
    print(("PASS %s" % name) if cond else ("FAIL %s: %s" % (name, why)), flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def recv_until(sock, needle, timeout=5.0, buf=b""):
    end = time.time() + timeout
    while needle not in buf and time.time() < end:
        sock.settimeout(max(0.05, end - time.time()))
        try:
            d = sock.recv(65536)
        except socket.timeout:
            continue
        if not d:
            break
        buf += d
    return buf


def flv_tags(data):
    """[(type, size, payload)] of an FLV file, or None if malformed"""
    if data[:3] != b"FLV":
        return None
    off, tags = struct.unpack(">I", data[5:9])[0] + 4, []
    while off + 11 <= len(data):
        t = data[off]
        n = struct.unpack(">I", b"\0" + data[off + 1:off + 4])[0]
        tags.append((t, n, data[off + 11:off + 11 + n]))
        off += 11 + n + 4
    return tags


tmp = tempfile.mkdtemp(prefix="rtmp-test-")
rport, hport = free_port(), free_port()
for d in ("logs", "rec", "hls", "conf"):
    os.makedirs(os.path.join(tmp, d))
conf = os.path.join(tmp, "conf", "nginx.conf")
with open(conf, "w") as f:
    f.write("""daemon off;
master_process off;
error_log %(t)s/logs/error.log info;
pid %(t)s/logs/nginx.pid;
events { worker_connections 64; }
rtmp {
  server {
    listen 127.0.0.1:%(r)d;
    application live {
      live on;
      record all;
      record_path %(t)s/rec;
      hls on;
      hls_path %(t)s/hls;
      hls_fragment 500ms;
    }
    application vod {
      play %(t)s/rec;
    }
  }
}
http {
  access_log off;
  client_body_temp_path %(t)s/logs/body;
  proxy_temp_path %(t)s/logs/proxy;
  fastcgi_temp_path %(t)s/logs/fcgi;
  uwsgi_temp_path %(t)s/logs/uwsgi;
  scgi_temp_path %(t)s/logs/scgi;
  server {
    listen 127.0.0.1:%(h)d;
    location /stat { rtmp_stat all; }
  }
}
""" % {"t": tmp, "r": rport, "h": hport})

srv = subprocess.Popen([NGINX, "-p", tmp + "/", "-c", conf],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    up = False
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", rport), timeout=0.2).close()
            up = True
            break
        except OSError:
            if srv.poll() is not None:
                break
            time.sleep(0.05)
    check("server_starts", up, "nginx did not listen on the RTMP port")

    publish = open(os.path.join(FIX, "publish.bin"), "rb").read()
    hs, body = publish[:3073], publish[3073:]

    pub = socket.create_connection(("127.0.0.1", rport), timeout=5) if up else None
    reply = b""
    if pub:
        pub.sendall(hs)
        end = time.time() + 5
        while len(reply) < 3073 and time.time() < end:
            d = pub.recv(65536)
            if not d:
                break
            reply += d
    # S0 = version 3; S1 = 1536 bytes; S2 echoes C1 (the plain handshake): 1536 zero bytes
    check("handshake_reply", len(reply) >= 3073 and reply[0] == 3 and reply[1537:3073] == bytes(1536),
          "got %d bytes, S0=%r" % (len(reply), reply[:1]))

    if pub:
        pub.sendall(body)
        reply = recv_until(pub, b"NetStream.Publish.Start", buf=reply[3073:])
    check("connect_result", b"_result" in reply and b"NetConnection.Connect.Success" in reply,
          "no _result/NetConnection.Connect.Success")
    check("publish_start", b"onStatus" in reply and b"NetStream.Publish.Start" in reply,
          "no NetStream.Publish.Start")

    time.sleep(0.5)
    xml = ""
    try:
        xml = urllib.request.urlopen("http://127.0.0.1:%d/stat" % hport, timeout=5).read().decode()
    except Exception as e:  # noqa
        xml = "error: %s" % e
    m = re.search(r"<stream>\s*<name>s</name>.*?</stream>", xml, re.S)
    st = m.group(0) if m else ""
    check("stat_stream_listed", st and "<publishing/>" in st and "<active/>" in st,
          "stream 's' not published in /stat")
    vid = re.search(r"<video>(.*?)</video>", st, re.S)
    vid = vid.group(1) if vid else ""
    check("stat_video_codec",
          all(x in vid for x in ("<width>320</width>", "<height>240</height>", "<codec>H264</codec>",
                                 "<profile>Baseline</profile>", "<level>3.0</level>")),
          "video section: %r" % vid)
    aud = re.search(r"<audio>(.*?)</audio>", st, re.S)
    aud = aud.group(1) if aud else ""
    check("stat_audio_codec",
          all(x in aud for x in ("<codec>AAC</codec>", "<profile>LC</profile>",
                                 "<channels>2</channels>", "<sample_rate>44100</sample_rate>")),
          "audio section: %r" % aud)

    if pub:
        pub.close()
    time.sleep(1.0)

    rec = os.path.join(tmp, "rec", "s.flv")
    data = open(rec, "rb").read() if os.path.exists(rec) else b""
    tags = flv_tags(data) or []
    v = [t for t in tags if t[0] == 9]
    a = [t for t in tags if t[0] == 8]
    sps = publish[publish.find(b"\x67\x42\xc0\x1e"):][:12]
    vframes = [t for t in v if t[2][1:2] == b"\x01"]
    aframes = [t for t in a if t[2][:2] == b"\xaf\x01"]
    keys = [t for t in vframes if t[2][0] == 0x17]
    check("record_flv",
          len(vframes) == 30 and len(keys) == 3 and len(aframes) == 30
          and v[0][2][:2] == b"\x17\x00" and sps in v[0][2] and a[0][2] == b"\xaf\x00\x12\x10",
          "recorded %d bytes: %d video (%d frames, %d key), %d audio (%d frames)"
          % (len(data), len(v), len(vframes), len(keys), len(a), len(aframes)))

    m3u8 = os.path.join(tmp, "hls", "s.m3u8")
    pl = open(m3u8).read() if os.path.exists(m3u8) else ""
    segs = re.findall(r"^(s-\d+\.ts)$", pl, re.M)
    ts_ok = bool(segs) and all(open(os.path.join(tmp, "hls", x), "rb").read(1) == b"\x47" for x in segs)
    check("hls_playlist", pl.startswith("#EXTM3U") and "#EXT-X-TARGETDURATION" in pl and ts_ok,
          "playlist %r" % pl[:200])

    play = open(os.path.join(FIX, "play_vod.bin"), "rb").read()
    got = b""
    if up:
        cl = socket.create_connection(("127.0.0.1", rport), timeout=5)
        cl.sendall(play)
        got = recv_until(cl, b"\xaf\x00\x12\x10", timeout=5)
        cl.close()
    check("vod_play_recording", b"NetStream.Play.Start" in got and b"\x17\x00\x00\x00\x00\x01\x42\xc0\x1e" in got and sps in got
          and b"\xaf\x00\x12\x10" in got,
          "player got %d bytes" % len(got))
finally:
    srv.terminate()
    try:
        srv.wait(5)
    except subprocess.TimeoutExpired:
        srv.kill()
    shutil.rmtree(tmp, ignore_errors=True)

print("RESULT %d %d" % (sum(results), len(results) - sum(results)))
