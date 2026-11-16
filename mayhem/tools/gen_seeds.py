#!/usr/bin/env python3
"""Generate the committed seed corpora (mayhem/<target>/testsuite/) and the functional-test
fixtures (mayhem/test/). Deterministic: re-running it rewrites identical files.

  python3 mayhem/tools/gen_seeds.py          (from the repo root)

Everything is hand-built from the specs: RTMP chunk stream + AMF0, an H.264 SPS/PPS for 320x240
Baseline, an AAC-LC 44.1 kHz stereo AudioSpecificConfig, and tiny FLV / MP4 files carrying them.
"""
import os
import struct
import random

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
rnd = random.Random(1935)

# ---------------------------------------------------------------- AMF0
def amf_num(v): return b"\x00" + struct.pack(">d", v)
def amf_bool(v): return b"\x01" + bytes([1 if v else 0])
def amf_str(s): s = s.encode(); return b"\x02" + struct.pack(">H", len(s)) + s
def amf_null(): return b"\x05"
def amf_key(k): k = k.encode(); return struct.pack(">H", len(k)) + k
def amf_obj(items):
    return b"\x03" + b"".join(amf_key(k) + v for k, v in items) + b"\x00\x00\x09"
def amf_ecma(items):
    return (b"\x08" + struct.pack(">I", len(items))
            + b"".join(amf_key(k) + v for k, v in items) + b"\x00\x00\x09")
def amf_strict(vals): return b"\x0a" + struct.pack(">I", len(vals)) + b"".join(vals)

# ---------------------------------------------------------------- RTMP chunk stream
class Chunker:
    def __init__(self, chunk=128):
        self.chunk = chunk
        self.out = bytearray()

    def msg(self, csid, mtype, msid, ts, payload):
        o = self.out
        o += bytes([csid & 0x3f])
        o += struct.pack(">I", ts)[1:] + struct.pack(">I", len(payload))[1:]
        o += bytes([mtype]) + struct.pack("<I", msid)
        for off in range(0, max(len(payload), 1), self.chunk):
            if off:
                o += bytes([0xc0 | csid])
            o += payload[off:off + self.chunk]
        return self

    def set_chunk_size(self, n):
        self.msg(2, 1, 0, 0, struct.pack(">I", n))
        self.chunk = n
        return self

    def cmd(self, msid, *vals, csid=3, ts=0):
        return self.msg(csid, 20, msid, ts, b"".join(vals))

def client_handshake():
    return b"\x03" + bytes(1536) + bytes(1536)

def server_handshake():
    s1 = bytes(8) + bytes(rnd.randrange(256) for _ in range(1528))
    return b"\x03" + s1 + bytes(1536)

def connect_cmd(app, extra=()):
    return [amf_str("connect"), amf_num(1),
            amf_obj([("app", amf_str(app)), ("flashVer", amf_str("LNX 9,0,124,2")),
                     ("tcUrl", amf_str("rtmp://127.0.0.1/" + app)),
                     ("fpad", amf_bool(False)), ("audioCodecs", amf_num(3575)),
                     ("videoCodecs", amf_num(252)), ("objectEncoding", amf_num(0))]
                    + list(extra))]

# ---------------------------------------------------------------- H.264 / AAC
class Bits:
    def __init__(self): self.b = []
    def u(self, n, v):
        for i in range(n - 1, -1, -1): self.b.append((v >> i) & 1)
    def ue(self, v):
        v += 1; n = v.bit_length()
        self.u(n - 1, 0); self.u(n, v)
    def se(self, v): self.ue(2 * v - 1 if v > 0 else -2 * v)
    def rbsp(self):
        self.b.append(1)
        while len(self.b) % 8: self.b.append(0)
        return bytes(int("".join(map(str, self.b[i:i + 8])), 2) for i in range(0, len(self.b), 8))

def sps(width=320, height=240):
    b = Bits()
    b.u(8, 66); b.u(8, 0xc0); b.u(8, 30)          # Baseline, constraint set 0+1, level 3.0
    b.ue(0); b.ue(0); b.ue(2); b.ue(1); b.u(1, 0)  # sps id, log2 frame num, poc type 2, refs
    b.ue(width // 16 - 1); b.ue(height // 16 - 1)
    b.u(1, 1); b.u(1, 1); b.u(1, 0); b.u(1, 0)     # frame_mbs_only, 8x8, no crop, no VUI
    return b"\x67" + b.rbsp()

def pps():
    b = Bits()
    b.ue(0); b.ue(0); b.u(1, 0); b.u(1, 0); b.ue(0); b.ue(0); b.ue(0)
    b.u(1, 0); b.u(2, 0); b.se(0); b.se(0); b.se(0); b.u(1, 1); b.u(1, 0); b.u(1, 0)
    return b"\x68" + b.rbsp()

SPS, PPS = sps(), pps()
AVCC = (bytes([1, SPS[1], SPS[2], SPS[3], 0xff, 0xe1]) + struct.pack(">H", len(SPS)) + SPS
        + b"\x01" + struct.pack(">H", len(PPS)) + PPS)
ASC = b"\x12\x10"                                   # AAC-LC, 44100 Hz, 2 channels

def nalu(t, n):
    return bytes([t]) + bytes(rnd.randrange(1, 256) for _ in range(n))

def avcc_frame(key):
    nals = [nalu(0x65 if key else 0x41, 60)]
    if key:
        nals.insert(0, b"\x06\x05\x01\x00\x80")    # SEI
    return b"".join(struct.pack(">I", len(x)) + x for x in nals)

def video_tag(key, payload):     # FLV/RTMP video payload, AVC NALU
    return bytes([0x17 if key else 0x27, 1, 0, 0, 0]) + payload

VIDEO_SEQ = bytes([0x17, 0, 0, 0, 0]) + AVCC
AUDIO_SEQ = bytes([0xaf, 0]) + ASC
def audio_frame(): return bytes([0xaf, 1]) + bytes(rnd.randrange(256) for _ in range(24))

METADATA = (amf_str("@setDataFrame") + amf_str("onMetaData") +
            amf_ecma([("duration", amf_num(0)), ("width", amf_num(320)),
                      ("height", amf_num(240)), ("videodatarate", amf_num(500)),
                      ("framerate", amf_num(25)), ("videocodecid", amf_num(7)),
                      ("audiodatarate", amf_num(128)), ("audiosamplerate", amf_num(44100)),
                      ("audiosamplesize", amf_num(16)), ("stereo", amf_bool(True)),
                      ("audiocodecid", amf_num(10)), ("encoder", amf_str("gen_seeds"))]))

def media(c, msid, frames=30, step=40):
    c.msg(4, 18, msid, 0, METADATA)
    c.msg(6, 9, msid, 0, VIDEO_SEQ)
    c.msg(4, 8, msid, 0, AUDIO_SEQ)
    for i in range(frames):
        ts = i * step
        c.msg(6, 9, msid, ts, video_tag(i % 10 == 0, avcc_frame(i % 10 == 0)))
        c.msg(4, 8, msid, ts, audio_frame())

# ---------------------------------------------------------------- client conversations
def publish_session(app, name="s", chunk=None, frames=30, unpublish=True):
    c = Chunker()
    if chunk:
        c.set_chunk_size(chunk)
    c.msg(2, 5, 0, 0, struct.pack(">I", 5000000))  # window ack size
    c.cmd(0, *connect_cmd(app))
    c.cmd(0, amf_str("releaseStream"), amf_num(2), amf_null(), amf_str(name))
    c.cmd(0, amf_str("FCPublish"), amf_num(3), amf_null(), amf_str(name))
    c.cmd(0, amf_str("createStream"), amf_num(4), amf_null())
    c.cmd(1, amf_str("publish"), amf_num(5), amf_null(), amf_str(name), amf_str("live"), csid=8)
    media(c, 1, frames)
    if not unpublish:
        return client_handshake() + bytes(c.out)
    c.cmd(1, amf_str("FCUnpublish"), amf_num(6), amf_null(), amf_str(name), csid=8)
    c.cmd(1, amf_str("deleteStream"), amf_num(7), amf_null(), amf_num(1), csid=8)
    return client_handshake() + bytes(c.out)

def play_session(app, name, extra=()):
    c = Chunker()
    c.cmd(0, *connect_cmd(app))
    c.cmd(0, amf_str("createStream"), amf_num(2), amf_null())
    c.msg(2, 4, 0, 0, struct.pack(">HII", 3, 1, 3000))          # user control: set buffer length
    c.cmd(1, amf_str("play"), amf_num(0), amf_null(), amf_str(name), amf_num(-2000),
          amf_num(-1), amf_bool(True), csid=8)
    for e in extra:
        c.cmd(1, *e, csid=8)
    return client_handshake() + bytes(c.out)

def misc_session():
    """odd but legal traffic: chunk size change mid-stream, acks, ping, shared object, abort,
    AMF3 command, call, close"""
    c = Chunker()
    c.cmd(0, *connect_cmd("live", [("pageUrl", amf_str("http://x/"))]))
    c.msg(2, 3, 0, 0, struct.pack(">I", 1000))                 # ack
    c.msg(2, 4, 0, 0, struct.pack(">HI", 6, 1234))            # ping request
    c.msg(2, 4, 0, 0, struct.pack(">HI", 7, 1234))            # ping response
    c.set_chunk_size(64)
    c.cmd(0, amf_str("createStream"), amf_num(2), amf_null())
    c.msg(2, 2, 0, 0, struct.pack(">I", 8))                    # abort csid 8
    c.msg(3, 17, 0, 0, b"\x00" + amf_str("getStreamLength") + amf_num(3) + amf_null()
          + amf_str("s"))                                       # AMF3 command
    c.set_chunk_size(4096)
    c.cmd(1, amf_str("play"), amf_num(0), amf_null(), amf_str("s"), csid=8)
    c.cmd(1, amf_str("pause"), amf_num(0), amf_null(), amf_bool(True), amf_num(0), csid=8)
    c.cmd(1, amf_str("pause"), amf_num(0), amf_null(), amf_bool(False), amf_num(0), csid=8)
    c.cmd(1, amf_str("seek"), amf_num(0), amf_null(), amf_num(500), csid=8)
    c.cmd(1, amf_str("closeStream"), amf_num(0), amf_null(), csid=8)
    return client_handshake() + bytes(c.out)

# ---------------------------------------------------------------- relay upstream (server side)
def relay_upstream(frames=20):
    c = Chunker()
    c.msg(2, 5, 0, 0, struct.pack(">I", 5000000))
    c.msg(2, 6, 0, 0, struct.pack(">IB", 5000000, 2))
    c.set_chunk_size(4096)
    c.cmd(0, amf_str("_result"), amf_num(1),
          amf_obj([("fmsVer", amf_str("FMS/3,0,1,123")), ("capabilities", amf_num(31))]),
          amf_obj([("level", amf_str("status")), ("code", amf_str("NetConnection.Connect.Success")),
                   ("description", amf_str("ok")), ("objectEncoding", amf_num(0))]))
    c.cmd(0, amf_str("_result"), amf_num(2), amf_null(), amf_num(1))
    c.msg(2, 4, 0, 0, struct.pack(">HI", 0, 1))               # stream begin
    c.cmd(1, amf_str("onStatus"), amf_num(0), amf_null(),
          amf_obj([("level", amf_str("status")), ("code", amf_str("NetStream.Play.Start")),
                   ("description", amf_str("go"))]), csid=5)
    c.msg(5, 18, 1, 0, amf_str("onMetaData") + METADATA[len(amf_str("@setDataFrame")) + len(amf_str("onMetaData")):])
    media(c, 1, frames)
    return server_handshake() + bytes(c.out)

# ---------------------------------------------------------------- FLV file
def flv_tag(t, ts, data):
    hdr = bytes([t]) + struct.pack(">I", len(data))[1:] + struct.pack(">I", ts & 0xffffff)[1:] \
        + bytes([ts >> 24]) + b"\x00\x00\x00"
    return hdr + data + struct.pack(">I", len(data) + 11)

def flv_file(frames=50, step=40):
    body_tags = [(9, 0, VIDEO_SEQ), (8, 0, AUDIO_SEQ)]
    for i in range(frames):
        ts = i * step
        body_tags.append((9, ts, video_tag(i % 10 == 0, avcc_frame(i % 10 == 0))))
        body_tags.append((8, ts, audio_frame()))
    nkeys = len([1 for i in range(frames) if i % 10 == 0])

    def meta(positions):
        times = [i * step / 1000.0 for i in range(frames) if i % 10 == 0]
        return flv_tag(18, 0, amf_str("onMetaData") + amf_ecma([
            ("duration", amf_num(frames * step / 1000.0)), ("width", amf_num(320)),
            ("height", amf_num(240)), ("videocodecid", amf_num(7)), ("audiocodecid", amf_num(10)),
            ("framerate", amf_num(25)),
            ("keyframes", amf_obj([("filepositions", amf_strict([amf_num(p) for p in positions])),
                                   ("times", amf_strict([amf_num(t) for t in times]))]))]))

    header = b"FLV\x01\x05\x00\x00\x00\x09" + b"\x00\x00\x00\x00"
    m = meta([0] * nkeys)
    pos, positions = len(header) + len(m), []
    tags = b""
    for i, (t, ts, d) in enumerate(body_tags):
        if t == 9 and i >= 2 and d[0] == 0x17:
            positions.append(pos + len(tags))
        tags += flv_tag(t, ts, d)
    return header + meta(positions) + tags

# ---------------------------------------------------------------- MP4 file
def box(t, *parts): d = b"".join(parts); return struct.pack(">I", 8 + len(d)) + t + d
def fbox(t, ver, flags, *parts): return box(t, struct.pack(">I", (ver << 24) | flags), *parts)
MATRIX = struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)

def mp4_file(frames=50, step=40):
    vs = [avcc_frame(i % 10 == 0) for i in range(frames)]
    aus = [bytes(rnd.randrange(256) for _ in range(24)) for _ in range(frames)]
    dur = frames * step

    def trak(tid, handler, entry, sizes, delta, timescale, offset, stss=None, ctts=False):
        stbl = [fbox(b"stsd", 0, 0, struct.pack(">I", 1), entry),
                fbox(b"stts", 0, 0, struct.pack(">III", 1, len(sizes), delta))]
        if ctts:
            stbl.append(fbox(b"ctts", 0, 0, struct.pack(">III", 1, len(sizes), 0)))
        if stss:
            stbl.append(fbox(b"stss", 0, 0, struct.pack(">I", len(stss)),
                             b"".join(struct.pack(">I", x) for x in stss)))
        stbl += [fbox(b"stsc", 0, 0, struct.pack(">IIII", 1, 1, len(sizes), 1)),
                 fbox(b"stsz", 0, 0, struct.pack(">II", 0, len(sizes)),
                      b"".join(struct.pack(">I", s) for s in sizes)),
                 fbox(b"stco", 0, 0, struct.pack(">II", 1, offset))]
        hd = (fbox(b"vmhd", 0, 1, bytes(8)) if handler == b"vide" else fbox(b"smhd", 0, 0, bytes(4)))
        minf = box(b"minf", hd, box(b"dinf", fbox(b"dref", 0, 0, struct.pack(">I", 1),
                                                    fbox(b"url ", 0, 1))), box(b"stbl", *stbl))
        mdia = box(b"mdia",
                   fbox(b"mdhd", 0, 0, struct.pack(">IIIIHH", 0, 0, timescale,
                                                    dur * timescale // 1000, 0x55c4, 0)),
                   fbox(b"hdlr", 0, 0, struct.pack(">I", 0), handler, bytes(12), b"\x00"), minf)
        w, h = (320, 240) if handler == b"vide" else (0, 0)
        tkhd = fbox(b"tkhd", 0, 3, struct.pack(">IIIII", 0, 0, tid, 0, dur), bytes(8),
                    struct.pack(">hhhH", 0, 0, 0x100 if handler == b"soun" else 0, 0), MATRIX,
                    struct.pack(">II", w << 16, h << 16))
        return box(b"trak", tkhd, mdia)

    avc1 = box(b"avc1", bytes(6), struct.pack(">H", 1), bytes(16), struct.pack(">HH", 320, 240),
               struct.pack(">II", 0x480000, 0x480000), bytes(4), struct.pack(">H", 1), bytes(32),
               struct.pack(">Hh", 0x18, -1), box(b"avcC", AVCC))
    esd = (b"\x03\x19\x00\x02\x00" + b"\x04\x11\x40\x15\x00\x00\x00" + struct.pack(">II", 128000, 128000)
           + b"\x05\x02" + ASC + b"\x06\x01\x02")
    mp4a = box(b"mp4a", bytes(6), struct.pack(">H", 1), bytes(8), struct.pack(">HHHH", 2, 16, 0, 0),
               struct.pack(">I", 44100 << 16), fbox(b"esds", 0, 0, esd))

    ftyp = box(b"ftyp", b"isom", struct.pack(">I", 0x200), b"isomiso2avc1mp41")

    def moov(voff, aoff):
        return box(b"moov",
                   fbox(b"mvhd", 0, 0, struct.pack(">IIII", 0, 0, 1000, dur), struct.pack(">IH", 0x10000, 0x100),
                        bytes(10), MATRIX, bytes(24), struct.pack(">I", 3)),
                   trak(1, b"vide", avc1, [len(x) for x in vs], 1000 * step // 1000, 1000, voff,
                        stss=[i + 1 for i in range(frames) if i % 10 == 0], ctts=True),
                   trak(2, b"soun", mp4a, [len(x) for x in aus], 1024, 44100, aoff))

    m = moov(0, 0)
    voff = len(ftyp) + len(m) + 8
    aoff = voff + sum(len(x) for x in vs)
    return ftyp + moov(voff, aoff) + box(b"mdat", b"".join(vs) + b"".join(aus))

# ---------------------------------------------------------------- AMF API seeds
def amf_seed(sel, cut1, cut2, body): return bytes([sel, cut1, cut2]) + body

def write(rel, data):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)

def main():
    T = "{}/testsuite/{}"  # mayhem/<target>/testsuite, target = binary name with "-"
    write(T.format("rtmp-session-fuzzer", "publish_live"), publish_session("live"))
    write(T.format("rtmp-session-fuzzer", "publish_live2_chunk4096"), publish_session("live2", chunk=4096))
    write(T.format("rtmp-session-fuzzer", "play_live"), play_session("live", "s"))
    write(T.format("rtmp-session-fuzzer", "play_vod_missing"), play_session("vod", "mp4:none.mp4"))
    write(T.format("rtmp-session-fuzzer", "misc_commands"), misc_session())
    write(T.format("rtmp-session-fuzzer", "connect_only"),
          client_handshake() + bytes(Chunker().cmd(0, *connect_cmd("live")).out))

    pub = publish_session("live", frames=10)
    write(T.format("rtmp-proxy-protocol-fuzzer", "tcp4"), b"PROXY TCP4 192.0.2.1 198.51.100.2 51234 1936\r\n" + pub)
    write(T.format("rtmp-proxy-protocol-fuzzer", "tcp6"), b"PROXY TCP6 2001:db8::1 2001:db8::2 51234 1936\r\n" + pub)
    write(T.format("rtmp-proxy-protocol-fuzzer", "unknown"), b"PROXY UNKNOWN\r\n" + pub)

    write(T.format("rtmp-mp4-vod-fuzzer", "avc_aac.mp4"), mp4_file())
    write(T.format("rtmp-flv-vod-fuzzer", "avc_aac.flv"), flv_file())

    write(T.format("rtmp-relay-fuzzer", "upstream_play"), relay_upstream())
    write(T.format("rtmp-relay-fuzzer", "upstream_error"), server_handshake() + bytes(
        Chunker().cmd(0, amf_str("_error"), amf_num(1), amf_null(),
                      amf_obj([("level", amf_str("error")),
                               ("code", amf_str("NetConnection.Connect.Rejected"))])).out))

    write(T.format("rtmp-notify-fuzzer", "ok"), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    write(T.format("rtmp-notify-fuzzer", "redirect_name"),
          b"HTTP/1.1 302 Found\r\nServer: x\r\nLocation: other\r\nContent-Length: 0\r\n\r\n")
    write(T.format("rtmp-notify-fuzzer", "redirect_rtmp"),
          b"HTTP/1.0 302 Moved\r\nLocation: rtmp://127.0.0.1:1/app/name\r\n\r\n")
    write(T.format("rtmp-notify-fuzzer", "forbidden"), b"HTTP/1.1 403 Forbidden\r\n\r\n")

    write(T.format("rtmp-amf-fuzzer", "connect"), amf_seed(0, 40, 200, b"".join(connect_cmd("live")[1:])))
    write(T.format("rtmp-amf-fuzzer", "play"), amf_seed(1, 10, 128, amf_num(0) + amf_null() + amf_str("s")
                                                        + amf_num(-2000) + amf_num(-1) + amf_bool(True)))
    write(T.format("rtmp-amf-fuzzer", "metadata"), amf_seed(2, 100, 180, METADATA[len(amf_str("@setDataFrame")):]))
    write(T.format("rtmp-amf-fuzzer", "metadata_mixed"), amf_seed(3, 30, 90, METADATA[len(amf_str("@setDataFrame")) + 3:]))
    write(T.format("rtmp-amf-fuzzer", "skip_values"), amf_seed(0x34, 50, 60, b"".join(connect_cmd("live"))
                                                               + amf_strict([amf_num(1), amf_str("x")])))

    # functional-test fixtures (mayhem/test.sh): a publish to app "live" (stream "s") and a player
    write("test/publish.bin", publish_session("live", frames=30, unpublish=False))
    write("test/play_vod.bin", play_session("vod", "s"))

if __name__ == "__main__":
    main()
