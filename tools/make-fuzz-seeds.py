#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io TLS.
#
# Ghoti.io TLS is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""Write the fuzz seed corpus from the RFC 8448 vectors.

The seeds are the RFC's own server flights, whole and cut after each message,
in the framing fuzz_client expects ([epoch][length][bytes] segments after an
options byte), and each message the parsers read, behind the option byte that
selects its parser. The record fuzzers (server, stream, record) take the RFC's
records, byte for byte, behind their option bytes; the two-endpoint pump takes
option bytes and a few mutation entries. Every byte of content comes from
tests/data/rfc8448; the only bytes written here are option bytes, the
three-byte mutation entries of the pump, the lengths that frame a segment, the
two-byte extension types edited in the RFC's ClientHello to take the server
down each of its refusals, and a few seven-byte plaintext records (a
change_cipher_spec, an alert) that need no key.
`--check` fails if a committed seed differs from what this writes.

The ticket seeds are the one place content is written here that no vector
holds: a ticket is sealed with a key the fuzz harness holds (session_one's, and
server_one's), because no mutation of a byte can make an authentic one, and a
server that never opens one never reaches the checks on what is inside. The
sealing is AES-256-GCM, written out below (the standard library has none) and
checked against two published test vectors before it is used.
"""

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "rfc8448"
CORPUS = ROOT / "tests" / "fuzz" / "corpus"


def load(name):
    out = {}
    for line in (DATA / (name + ".vec")).read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split(" ", 1)
            out[key] = bytes.fromhex(value)
    return out


# ---------------------------------------------------------------- AES-256-GCM

def _sbox():
    box = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09

        def rotl(x, s):
            return ((x << s) | (x >> (8 - s))) & 0xFF

        box[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63
        if p == 1:
            break
    box[0] = 0x63
    return box


_S = _sbox()
assert _S[0x00] == 0x63 and _S[0x01] == 0x7C and _S[0x53] == 0xED


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _round_keys(key):
    assert len(key) == 32
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [_S[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [_S[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(15)]


def _encrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 15):
        s = [_S[b] for b in s]
        s = [s[4 * ((c + row) % 4) + row] for c in range(4) for row in range(4)]
        if r != 14:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3],
                        a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3],
                        a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3]),
                        (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])]
            s = out
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def _gmul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def gcm_seal(key, iv, aad, plain):
    """AES-256-GCM with a 96-bit IV: (ciphertext, 16-byte tag)."""
    assert len(iv) == 12
    rk = _round_keys(key)
    h = int.from_bytes(_encrypt_block(rk, bytes(16)), "big")
    counter = int.from_bytes(iv + b"\x00\x00\x00\x02", "big")
    ct = b""
    for off in range(0, len(plain), 16):
        ks = _encrypt_block(rk, counter.to_bytes(16, "big"))
        chunk = plain[off:off + 16]
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter = (counter & ~0xFFFFFFFF) | (((counter & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)

    def pad(b):
        return b + bytes(-len(b) % 16)

    data = pad(aad) + pad(ct) + struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    g = 0
    for off in range(0, len(data), 16):
        g = _gmul(g ^ int.from_bytes(data[off:off + 16], "big"), h)
    j0 = _encrypt_block(rk, iv + b"\x00\x00\x00\x01")
    tag = (int.from_bytes(j0, "big") ^ g).to_bytes(16, "big")
    return ct, tag


# McGrew and Viega's test cases 13 and 14 (AES-256, a zero key and IV).
assert gcm_seal(bytes(32), bytes(12), b"", b"")[1].hex() == "530f8afbc74536b9a963b4f1c4cb738b"
_c, _t = gcm_seal(bytes(32), bytes(12), b"", bytes(16))
assert _c.hex() == "cea7403d4d606b6e074ec5d3baf39d18" and _t.hex() == "d0d1c8a799996bf0265b98b5d48ab919"


def ticket_state(suite=0x1301, psk_len=None, age_add=0, issued=1700000000 - 4, lifetime=3600,
                 alpn=b"", sni=b"server", version=1, alpn_len=None, sni_len=None, tail=b"",
                 early=None):
    """The state a ticket seals (session/ticket.c), with any field made wrong on request.
    `early` is the allowance of a version 2 state, written after the lifetime."""
    hlen = 48 if suite == 0x1302 else 32
    n = hlen if psk_len is None else psk_len
    if early is not None and version == 1:
        version = 2
    st = bytes([version]) + struct.pack(">H", suite) + bytes([n]) + bytes([0x55]) * n
    st += struct.pack(">IqI", age_add, issued, lifetime)
    if early is not None:
        st += struct.pack(">I", early)
    st += bytes([len(alpn) if alpn_len is None else alpn_len]) + alpn
    st += bytes([len(sni) if sni_len is None else sni_len]) + sni
    return st + tail


def seal_ticket(name_byte, key_byte, state, nonce_seed=1):
    """A ticket as the library writes it: name, nonce, ciphertext, tag."""
    name = bytes([name_byte]) * 16
    nonce = bytes((nonce_seed + i) & 0xFF for i in range(12))
    aad = b"ghoti.io tls ticket v1" + name + nonce
    ct, tag = gcm_seal(bytes([key_byte]) * 32, nonce, aad, state)
    return name + nonce + ct + tag


def segment(epoch, data):
    return bytes([epoch]) + len(data).to_bytes(2, "big") + data


def split_messages(flight):
    out = []
    at = 0
    while at + 4 <= len(flight):
        n = 4 + int.from_bytes(flight[at + 1:at + 4], "big")
        out.append(flight[at:at + n])
        at += n
    assert at == len(flight)
    return out


def main():
    check = "--check" in sys.argv
    simple = load("simple-1rtt")
    hrr = load("hrr")
    nst = simple["server.construct-a-newsessionticket-handshake-message.newsessionticket"]
    resumed = load("resumed")
    seeds = {"client": {}, "msg": {}, "server": {}, "stream": {}, "record": {}, "pump": {},
             "resume": {}, "session": {}}

    def flight(v, name, extra_initial):
        sh = v["server.construct-a-serverhello-handshake-message%s.serverhello" % ("@2" if extra_initial else "")]
        body = v["server.send-handshake-record@%d.payload" % (3 if extra_initial else 2)]
        msgs = split_messages(body)
        opt = 1 if extra_initial else 0
        prefix = bytes([opt])
        if extra_initial:
            prefix += segment(0, v["server.construct-a-serverhello-handshake-message.serverhello"])
        prefix += segment(0, sh)
        seeds["client"][name + "-sh"] = prefix
        for i in range(1, len(msgs) + 1):
            seeds["client"][name + "-flight-%d" % i] = prefix + segment(2, b"".join(msgs[:i]))
        seeds["client"][name + "-whole"] = prefix + segment(2, body)
        seeds["client"][name + "-whole-and-ticket"] = prefix + segment(2, body) + segment(3, nst)
        seeds["client"][name + "-cut-opt"] = bytes([opt | (1 << 1)]) + prefix[1:] + segment(2, body) + segment(3, nst)
        seeds["client"][name + "-tight-limits"] = bytes([opt | 0x10]) + prefix[1:] + segment(2, body)
        return msgs

    msgs = flight(simple, "simple", False)
    flight(hrr, "hrr", True)
    seeds["client"]["wrong-epoch"] = bytes([0]) + segment(2, simple["server.construct-a-serverhello-handshake-message.serverhello"])

    ch = simple["client.construct-a-clienthello-handshake-message.clienthello"]
    sh = simple["server.construct-a-serverhello-handshake-message.serverhello"]
    hsh = hrr["server.construct-a-serverhello-handshake-message.serverhello"]
    fin = simple["server.construct-a-finished-handshake-message.finished"]
    flight = simple["server.send-handshake-record@2.payload"]
    named = [
        (0, "server-hello", sh[4:]),
        (0, "hello-retry-request", hsh[4:]),
        (1, "encrypted-extensions", msgs[0][4:]),
        (2, "certificate", msgs[1][4:]),
        (3, "certificate-verify", msgs[2][4:]),
        (4, "new-session-ticket", nst[4:]),
        (5, "client-hello", ch[4:]),
        (6, "retry-client-hello", ch[4:]),
        (7, "client-hello-extensions", ch[4:]),
        (7, "client-hello-extensions-retry", hrr["client.construct-a-clienthello-handshake-message@2.clienthello"][4:]),
        (8, "finished", fin[4:]),
        (8, "finished-sha384", fin[4:] + fin[4:][:16]),
        (8, "key-update", bytes([1])),
        (9, "build-encrypted-extensions", msgs[0][4:]),
        (10, "build-certificate", msgs[1][4:]),
        (11, "build-certificate-verify", msgs[2][4:]),
        (12, "build-server-hello", sh[4:]),
    ]
    for opt, name, body in named:
        seeds["msg"][name] = bytes([opt]) + body

    # Resumption: the RFC's resumed ClientHello (a PSK of one identity and one
    # binder, beside early_data) and ServerHello (the PSK selected). The high
    # nibble of the option byte is the cap on extensions, which has to be big
    # enough for the hello's eleven; bits 6 and 7 of the retry's option give it
    # a PSK to write, with a binder of 32 or 48 bytes.
    r_ch = resumed["client.send-handshake-record.payload"]
    r_sh = resumed["server.construct-a-serverhello-handshake-message.serverhello"]
    seeds["msg"]["psk-client-hello-extensions"] = bytes([0xf7]) + r_ch[4:]
    seeds["msg"]["psk-retry-client-hello"] = bytes([0xe6]) + r_ch[4:]
    seeds["msg"]["psk-retry-client-hello-share"] = bytes([0xf6]) + r_ch[4:]
    seeds["msg"]["psk-retry-client-hello-plain"] = bytes([0xb6]) + r_ch[4:]
    seeds["msg"]["psk-server-hello"] = bytes([0x30]) + r_sh[4:]

    # The server, fed the RFC's client records. Option bits: 0 the retry trace,
    # 1-3 the feed size, 4 a server that wants P-256 only, 5 act when done,
    # 6 small limits, 7 end of stream at the end.
    c_ch = simple["client.send-handshake-record.complete-record"]
    c_fin = simple["client.send-handshake-record@2.complete-record"]
    c_app = simple["client.send-application-data-record.complete-record"]
    c_alert = simple["client.send-alert-record.complete-record"]
    h_ch1 = hrr["client.send-handshake-record.complete-record"]
    h_ch2 = hrr["client.send-handshake-record@2.complete-record"]
    h_fin = hrr["client.send-handshake-record@3.complete-record"]
    h_alert = hrr["client.send-alert-record.complete-record"]
    srv = seeds["server"]
    srv["hello"] = bytes([0]) + c_ch
    srv["hello-and-finished"] = bytes([0]) + c_ch + c_fin
    srv["whole"] = bytes([0]) + c_ch + c_fin + c_app + c_alert
    srv["whole-act"] = bytes([0x20]) + c_ch + c_fin + c_app
    srv["whole-act-eof"] = bytes([0xa0]) + c_ch + c_fin + c_app
    srv["whole-small-limits"] = bytes([0x40]) + c_ch + c_fin + c_app
    srv["whole-bytewise"] = bytes([0x02]) + c_ch + c_fin + c_app + c_alert
    srv["whole-in-threes"] = bytes([0x06]) + c_ch + c_fin + c_app + c_alert
    srv["truncated-hello"] = bytes([0x80]) + c_ch[:len(c_ch) // 2]
    srv["eof-before-anything"] = bytes([0x80])
    srv["retry-from-simple-hello"] = bytes([0x10]) + c_ch
    srv["retry-then-hello-again"] = bytes([0x10]) + c_ch + c_ch
    srv["retry-trace"] = bytes([0x11]) + h_ch1 + h_ch2 + h_fin + h_alert
    srv["retry-trace-bytewise"] = bytes([0x13]) + h_ch1 + h_ch2 + h_fin
    srv["unexpected-hello-after-flight"] = bytes([0]) + c_ch + c_ch
    srv["app-data-first"] = bytes([0]) + c_app

    # The server, fed the RFC's ClientHello with one field edited in place (the
    # lengths do not change): the paths a refusal takes.
    def edit(record, old, new):
        assert record.count(old) == 1, old.hex()
        return record.replace(old, new)

    srv["refuse-compression"] = bytes([0]) + c_ch[:5 + 48] + b"\x01" + c_ch[5 + 49:]
    srv["refuse-no-versions"] = bytes([0]) + edit(c_ch, bytes.fromhex("002b0003020304"), bytes.fromhex("0a2b0003020304"))
    # A pre_shared_key anywhere but last, and an early_data with a body: both
    # are refused by shape (the first extension of the RFC's hello is edited).
    srv["refuse-psk-not-last"] = bytes([0]) + edit(c_ch, bytes.fromhex("001c00024001"), bytes.fromhex("002900024001"))
    srv["refuse-early-data-body"] = bytes([0]) + edit(c_ch, bytes.fromhex("001c00024001"), bytes.fromhex("002a00024001"))

    # A pre_shared_key and an early_data extension appended to the RFC's
    # hello, which fixes up its three lengths. The server ignores the offer,
    # skips the early-data records, and reads the (now wrong) Finished.
    def with_ext(record, ext_type, body):
        ext = struct.pack(">HH", ext_type, len(body)) + body
        hs = record[5:]
        assert hs[0] == 1 and record[0] == 22
        sid = 4 + 2 + 32
        at = sid + 1 + hs[sid]
        at += 2 + struct.unpack(">H", hs[at:at + 2])[0]
        at += 1 + hs[at]
        ext_len = struct.unpack(">H", hs[at:at + 2])[0]
        assert at + 2 + ext_len == len(hs)
        hs = hs[:at] + struct.pack(">H", ext_len + len(ext)) + hs[at + 2:] + ext
        hs = hs[:1] + struct.pack(">I", len(hs) - 4)[1:] + hs[4:]
        return record[:3] + struct.pack(">H", len(hs)) + hs

    def psk_body(identities, binders, binder_len=32, id_len=8, last_id_len=None, first_binder_len=None):
        ids = b""
        for i in range(identities):
            n = last_id_len if (last_id_len is not None and i == identities - 1) else id_len
            ids += struct.pack(">H", n) + bytes([0x50 + i]) * n + b"\x00\x00\x12\x34"
        bnd = b""
        for i in range(binders):
            n = first_binder_len if (first_binder_len is not None and i == 0) else binder_len
            bnd += bytes([n]) + bytes([0x60 + i]) * n
        return struct.pack(">H", len(ids)) + ids + struct.pack(">H", len(bnd)) + bnd

    def strip_ext(record, ext_type):
        """The record without every extension of this type, the three lengths fixed up."""
        hs = record[5:]
        sid = 4 + 2 + 32
        at = sid + 1 + hs[sid]
        at += 2 + struct.unpack(">H", hs[at:at + 2])[0]
        at += 1 + hs[at]
        ext_len = struct.unpack(">H", hs[at + 0:at + 2])[0]
        exts = hs[at + 2:at + 2 + ext_len]
        out, k = b"", 0
        while k < len(exts):
            t, n = struct.unpack(">HH", exts[k:k + 4])
            if t != ext_type:
                out += exts[k:k + 4 + n]
            k += 4 + n
        hs = hs[:at] + struct.pack(">H", len(out)) + out
        hs = hs[:1] + struct.pack(">I", len(hs) - 4)[1:] + hs[4:]
        return record[:3] + struct.pack(">H", len(hs)) + hs

    def early_record(n):
        return b"\x17\x03\x03" + struct.pack(">H", n) + b"\xa5" * n

    ch_psk = with_ext(c_ch, 0x29, psk_body(1, 1))
    ch_early_only = with_ext(c_ch, 0x2a, b"")
    ch_early = with_ext(ch_early_only, 0x29, psk_body(1, 1))     # early_data beside a PSK: the window opens
    ch_psk_early = with_ext(ch_early_only, 0x29, psk_body(2, 2))
    srv["psk-offer"] = bytes([0]) + ch_psk + c_fin
    srv["psk-offer-bad-count"] = bytes([0]) + with_ext(c_ch, 0x29, psk_body(2, 1))
    srv["psk-offer-short-binder"] = bytes([0]) + with_ext(c_ch, 0x29, psk_body(2, 2, 8))
    srv["psk-offer-binder-31"] = bytes([0]) + with_ext(c_ch, 0x29, psk_body(2, 2, first_binder_len=31))
    srv["psk-offer-empty-identity"] = bytes([0]) + with_ext(c_ch, 0x29, psk_body(2, 2, last_id_len=0))
    srv["psk-offer-no-identities"] = bytes([0]) + with_ext(c_ch, 0x29, psk_body(0, 1))
    # The small-limits server allows one identity of 12 bytes: each cap's LIMIT return.
    srv["psk-offer-too-many-identities"] = bytes([0x40]) + with_ext(c_ch, 0x29, psk_body(2, 2))
    srv["psk-offer-identity-too-long"] = bytes([0x40]) + with_ext(c_ch, 0x29, psk_body(1, 1, id_len=13))
    srv["psk-offer-too-many-binders"] = bytes([0x40]) + with_ext(c_ch, 0x29, psk_body(1, 2))
    srv["psk-offer-at-the-limits"] = bytes([0x40]) + with_ext(c_ch, 0x29, psk_body(1, 1, id_len=12))
    srv["psk-without-modes"] = bytes([0]) + with_ext(strip_ext(c_ch, 45), 0x29, psk_body(1, 1))
    srv["psk-with-bad-modes"] = bytes([0]) + with_ext(edit(c_ch, bytes.fromhex("002d00020101"), bytes.fromhex("002d00020501")), 0x29, psk_body(1, 1))
    srv["early-data-body"] = bytes([0]) + with_ext(c_ch, 0x2a, b"\x00\x00")
    srv["early-data-skipped"] = bytes([0]) + ch_early + early_record(40) + early_record(300) + c_fin + c_app
    srv["early-data-skipped-bytewise"] = bytes([0x02]) + ch_psk_early + early_record(60) + c_fin + c_app
    srv["early-data-small-limits"] = bytes([0x40]) + ch_early + early_record(40) + early_record(300) + c_fin
    srv["early-data-then-garbage"] = bytes([0]) + ch_early + early_record(40) + c_fin + early_record(20)
    srv["early-data-after-retry"] = bytes([0x10]) + ch_early + early_record(40) + early_record(16384 + 256) + c_ch
    srv["early-data-retry-dropped"] = bytes([0x10]) + ch_early + early_record(40) + ch_psk
    srv["early-data-in-second-hello"] = bytes([0x10]) + ch_early + early_record(40) + ch_early
    srv["early-data-between-fragments"] = bytes([0x10]) + ch_early + early_record(40) + ch_psk[:5].replace(ch_psk[3:5], struct.pack(">H", 50)) + ch_psk[5:55] + early_record(40)
    srv["early-data-without-psk"] = bytes([0]) + ch_early_only + early_record(40)
    srv["no-early-data-then-garbage"] = bytes([0]) + c_ch + early_record(40)
    srv["refuse-cookie"] = bytes([0]) + edit(c_ch, bytes.fromhex("001c00024001"), bytes.fromhex("002c00024001"))
    srv["refuse-bad-alpn"] = bytes([0]) + edit(c_ch, bytes.fromhex("001c00024001"), bytes.fromhex("001000024001"))
    srv["refuse-plain-alert-after-hello"] = bytes([0]) + c_ch + bytes.fromhex("1503030002 0100".replace(" ", ""))
    srv["refuse-plain-alert-first"] = bytes([0]) + bytes.fromhex("15030300020100")
    srv["refuse-ccs-first"] = bytes([0]) + bytes.fromhex("140303000101") + c_ch
    srv["ccs-after-hello"] = bytes([0]) + c_ch + bytes.fromhex("140303000101") + c_fin
    srv["refuse-wrong-size-alert"] = bytes([0]) + c_ch + bytes.fromhex("150303000301 0000".replace(" ", ""))

    # Tickets, for the server. server_one's keyring is one key whose name and
    # bytes are all 0x6b, and the clock is 1700000000; a ticket sealed under it
    # is authentic, so the checks on what it says are reached (a binder that is
    # wrong ends each of these that qualifies). The RFC's hello names "server".
    def hs_fix(record, hs):
        hs = hs[:1] + struct.pack(">I", len(hs) - 4)[1:] + hs[4:]
        return record[:3] + struct.pack(">H", len(hs)) + hs

    def set_suites(record, suites):
        hs = record[5:]
        at = 4 + 2 + 32
        at += 1 + hs[at]
        old = struct.unpack(">H", hs[at:at + 2])[0]
        new = b"".join(struct.pack(">H", x) for x in suites)
        return hs_fix(record, hs[:at] + struct.pack(">H", len(new)) + new + hs[at + 2 + old:])

    def replace_ext(record, ext_type, body):
        hs = record[5:]
        at = 4 + 2 + 32
        at += 1 + hs[at]
        at += 2 + struct.unpack(">H", hs[at:at + 2])[0]
        at += 1 + hs[at]
        ext_len = struct.unpack(">H", hs[at:at + 2])[0]
        exts = hs[at + 2:at + 2 + ext_len]
        out, k, found = b"", 0, False
        while k < len(exts):
            t, n = struct.unpack(">HH", exts[k:k + 4])
            if t == ext_type:
                out += struct.pack(">HH", t, len(body)) + body
                found = True
            else:
                out += exts[k:k + 4 + n]
            k += 4 + n
        assert found
        return hs_fix(record, hs[:at] + struct.pack(">H", len(out)) + out)

    def psk_ticket(ticket, binder_len=32):
        ids = struct.pack(">H", len(ticket)) + ticket + b"\x00\x00\x12\x34"
        bnd = bytes([binder_len]) + bytes([0x60]) * binder_len
        return struct.pack(">H", len(ids)) + ids + struct.pack(">H", len(bnd)) + bnd

    def server_ticket(suite):
        return seal_ticket(0x6b, 0x6b, ticket_state(suite=suite))

    p256_share = struct.pack(">H", 2 + 2 + 65) + struct.pack(">HH", 0x0017, 65) + b"\x04" + bytes(range(64))
    srv["ticket-resumes-binder-wrong"] = bytes([0]) + with_ext(c_ch, 0x29, psk_ticket(server_ticket(0x1301)))
    srv["ticket-suite-not-offered"] = bytes([0]) + with_ext(set_suites(c_ch, [0x1301]), 0x29, psk_ticket(server_ticket(0x1303)))
    srv["ticket-suite-not-in-context"] = bytes([0x08]) + with_ext(c_ch, 0x29, psk_ticket(server_ticket(0x1302)))
    srv["ticket-issue-limit"] = bytes([0x08]) + c_ch + c_fin
    srv["ticket-retry-other-suite"] = bytes([0x10]) + with_ext(c_ch, 0x29, psk_body(1, 1)) + \
        with_ext(replace_ext(c_ch, 0x33, p256_share), 0x29, psk_ticket(server_ticket(0x1303)))
    srv["ticket-retry-same-suite"] = bytes([0x10]) + with_ext(c_ch, 0x29, psk_body(1, 1)) + \
        with_ext(replace_ext(c_ch, 0x33, p256_share), 0x29, psk_ticket(server_ticket(0x1301)))
    srv["ticket-for-another-name"] = bytes([0]) + with_ext(c_ch, 0x29, psk_ticket(
        seal_ticket(0x6b, 0x6b, ticket_state(sni=b"other"))))
    srv["ticket-expired"] = bytes([0]) + with_ext(c_ch, 0x29, psk_ticket(
        seal_ticket(0x6b, 0x6b, ticket_state(issued=1700000000 - 100000))))
    srv["ticket-of-an-unknown-key"] = bytes([0]) + with_ext(c_ch, 0x29, psk_ticket(
        seal_ticket(0x6b, 0x6a, ticket_state())))

    # Early data (spec 8b). A ticket whose state is version 2 carries an
    # allowance; a ClientHello that offers it with early_data, with a binder that
    # is right (computed here from the RFC's hashes: SHA-384, HMAC and HKDF are in
    # the standard library) opens the early key, and the records after it are
    # sealed under that key (AES-256-GCM, written out above). The server accepts
    # when the size of the whole input is even, and refuses when it is odd (the
    # harness's replay decision), so a pad byte after the records, which a
    # server in S_WAIT_FIN reads as the start of a record, chooses.
    import hmac as _hmac

    def _expand_label(h, secret, label, context, length):
        info = struct.pack(">H", length) + bytes([6 + len(label)]) + b"tls13 " + label + bytes([len(context)]) + context
        out, block, i = b"", b"", 1
        while len(out) < length:
            block = _hmac.new(secret, block + info + bytes([i]), h).digest()
            out += block
            i += 1
        return out[:length]

    def early_flight(suite=0x1302, allowance=100, ticket_kw=None, alpn=None, extra_ext=True):
        """(ClientHello record, the early key and IV, hash name) for a ticket sealed
        under server_one's key with this allowance."""
        h = hashlib.sha384 if suite == 0x1302 else hashlib.sha256
        hl = 48 if suite == 0x1302 else 32
        psk = bytes([0x55]) * hl
        kw = dict(suite=suite, early=allowance)
        kw.update(ticket_kw or {})
        ticket = seal_ticket(0x6b, 0x6b, ticket_state(**kw))
        rec = c_ch
        if alpn is not None:
            lst = bytes([len(alpn)]) + alpn
            rec = with_ext(rec, 0x10, struct.pack(">H", len(lst)) + lst)
        if extra_ext:
            rec = with_ext(rec, 0x2a, b"")
        ids = struct.pack(">H", len(ticket)) + ticket + b"\x00\x00\x00\x00"
        placeholder = struct.pack(">H", len(ids)) + ids + struct.pack(">H", 1 + hl) + bytes([hl]) + bytes(hl)
        rec = with_ext(rec, 0x29, placeholder)
        hs = rec[5:]
        early = _hmac.new(bytes(hl), psk, h).digest()
        binder_key = _expand_label(h, early, b"res binder", h(b"").digest(), hl)
        fin_key = _expand_label(h, binder_key, b"finished", b"", hl)
        binder = _hmac.new(fin_key, h(hs[:-(2 + 1 + hl)]).digest(), h).digest()
        hs = hs[:-hl] + binder
        rec = rec[:5] + hs
        c_e = _expand_label(h, early, b"c e traffic", h(hs).digest(), hl)
        key = _expand_label(h, c_e, b"key", b"", 32)
        iv = _expand_label(h, c_e, b"iv", b"", 12)
        return rec, key, iv

    def seal_record(key, iv, seq, inner_type, data):
        nonce = bytes(a ^ b for a, b in zip(iv, bytes(4) + struct.pack(">Q", seq)))
        plain = data + bytes([inner_type])
        header = b"\x17\x03\x03" + struct.pack(">H", len(plain) + 16)
        ct, tag = gcm_seal(key, nonce, header, plain)
        return header + ct + tag

    def even_input(opt, build):
        """build(n) with n bytes of early data, with n chosen so that the input, opt included, is even."""
        for n in (40, 41):
            body = build(n)
            if (1 + len(body)) % 2 == 0:
                return bytes([opt]) + body
        return bytes([opt]) + body + b"\x00"   # a stray byte, which a server reads as the start of a record

    def odd_input(opt, build):
        for n in (40, 41):
            body = build(n)
            if (1 + len(body)) % 2 == 1:
                return bytes([opt]) + body
        return bytes([opt]) + body + b"\x00"   # a stray byte, which a server reads as the start of a record

    ch_e, ek, eiv = early_flight()
    eoed = lambda seq: seal_record(ek, eiv, seq, 22, bytes([5, 0, 0, 0]))
    srv["early-accepted"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + c_fin)
    srv["early-accepted-bytewise"] = even_input(0x02, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + c_fin)
    srv["early-accepted-act"] = even_input(0x20, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + c_fin)
    srv["early-accepted-small-limits"] = even_input(0x40, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + c_fin)
    srv["early-accepted-two-records"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + seal_record(ek, eiv, 1, 23, b"F" * 20) + eoed(2) + c_fin)
    srv["early-refused-by-the-callback"] = odd_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + c_fin)
    srv["early-no-end"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + c_fin)
    srv["early-end-first"] = even_input(0x00, lambda n: ch_e + eoed(0) + c_fin)
    srv["early-bad-record"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n)[:-1] + b"\x00" + eoed(1))
    srv["early-over-the-allowance"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * 60) + seal_record(ek, eiv, 1, 23, b"E" * (n + 20)))
    srv["early-exactly-the-allowance"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * 100) + eoed(1) + c_fin[:n % 3])
    srv["early-eoed-with-a-body"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + seal_record(ek, eiv, 1, 22, bytes([5, 0, 0, 1, 0])))
    srv["early-eoed-twice"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1) + eoed(2))
    srv["early-wrong-message-for-eoed"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 23, b"E" * n) + seal_record(ek, eiv, 1, 22, bytes([20, 0, 0, 0])))
    srv["early-alert-in-the-early-phase"] = even_input(0x00, lambda n: ch_e + seal_record(ek, eiv, 0, 21, bytes([1, 0])))
    srv["early-ccs-in-the-early-phase"] = even_input(0x00, lambda n: ch_e + bytes.fromhex("140303000101") + seal_record(ek, eiv, 0, 23, b"E" * n) + eoed(1))
    ch_small, sk, siv = early_flight(allowance=4)
    srv["early-empty-records-end-it"] = even_input(0x00, lambda n: ch_small + b"".join(seal_record(sk, siv, i, 23, b"") for i in range(6)) + c_fin[:n % 2])
    ch_alpn, ak, aiv = early_flight(alpn=b"http/1.1")
    srv["early-refused-alpn-differs"] = even_input(0x00, lambda n: ch_alpn + seal_record(ak, aiv, 0, 23, b"E" * n) + c_fin)
    ch_none, nk, niv = early_flight(allowance=0, ticket_kw={"early": None})
    srv["early-ticket-without-an-allowance"] = even_input(0x00, lambda n: ch_none + seal_record(nk, niv, 0, 23, b"E" * n) + c_fin)
    ch_256, k256, iv256 = early_flight(suite=0x1301)
    srv["early-sha256-suite"] = even_input(0x00, lambda n: ch_256 + c_fin[:n % 2])
    ch_retry_e, rk, riv = early_flight()
    srv["early-then-retry"] = even_input(0x10, lambda n: ch_retry_e + seal_record(rk, riv, 0, 23, b"E" * n) + c_ch)

    # The client, fed the RFC's server records.
    s_sh = simple["server.send-handshake-record.complete-record"]
    s_flight = simple["server.send-handshake-record@2.complete-record"]
    s_nst = simple["server.send-handshake-record@3.complete-record"]
    s_app = simple["server.send-application-data-record.complete-record"]
    s_alert = simple["server.send-alert-record.complete-record"]
    h_hrr = hrr["server.send-handshake-record.complete-record"]
    h_sh = hrr["server.send-handshake-record@2.complete-record"]
    h_flight = hrr["server.send-handshake-record@3.complete-record"]
    st = seeds["stream"]
    st["hello"] = bytes([0]) + s_sh
    st["hello-and-flight"] = bytes([0]) + s_sh + s_flight
    st["whole"] = bytes([0]) + s_sh + s_flight + s_nst + s_app + s_alert
    st["whole-act"] = bytes([0x20]) + s_sh + s_flight + s_nst + s_app
    st["whole-act-eof"] = bytes([0xa0]) + s_sh + s_flight + s_nst + s_app
    st["whole-small-limits"] = bytes([0x40]) + s_sh + s_flight + s_nst + s_app
    st["whole-bytewise"] = bytes([0x02]) + s_sh + s_flight + s_nst + s_app + s_alert
    st["whole-in-threes"] = bytes([0x06]) + s_sh + s_flight + s_nst + s_app + s_alert
    st["truncated-flight"] = bytes([0x80]) + s_sh + s_flight[:len(s_flight) // 2]
    st["retry-trace"] = bytes([0x01]) + h_hrr + h_sh + h_flight + hrr["server.send-alert-record.complete-record"]
    st["retry-trace-bytewise"] = bytes([0x03]) + h_hrr + h_sh + h_flight
    st["retry-trace-act"] = bytes([0x21]) + h_hrr + h_sh + h_flight
    st["alert-first"] = bytes([0]) + s_alert
    st["plain-close-notify"] = bytes([0]) + bytes.fromhex("15030300020100")
    st["plain-close-notify-after-hello"] = bytes([0]) + s_sh + bytes.fromhex("15030300020100")
    st["wrong-size-plain-alert"] = bytes([0]) + s_sh + bytes.fromhex("150303000301 0000".replace(" ", ""))
    st["ccs-between-hello-and-flight"] = bytes([0]) + s_sh + bytes.fromhex("140303000101") + s_flight
    st["ccs-three-times"] = bytes([0]) + s_sh + bytes.fromhex("140303000101140303000101140303000101") + s_flight
    st["ccs-after-connected"] = bytes([0]) + s_sh + s_flight + bytes.fromhex("140303000101")
    st["plain-alert-connected"] = bytes([0]) + s_sh + s_flight + bytes.fromhex("15030300020100")

    # The record layer: seal-and-open (option bits 0-1 suite, 2 padding), and
    # open-only on real records.
    rc = seeds["record"]
    rc["seal-aes128"] = bytes([0]) + flight[:100]
    rc["seal-aes256-padded"] = bytes([5]) + flight[:300]
    rc["seal-chacha"] = bytes([2]) + nst
    rc["seal-empty"] = bytes([0])
    rc["open-trace-record"] = bytes([8]) + s_flight
    rc["open-trace-app"] = bytes([8]) + s_app
    rc["open-trace-alert"] = bytes([10]) + s_alert

    # Two endpoints. Option bits: 0-1 suite (3 is the default order), 2-3 group
    # (3 the default order), 4 a server that wants P-256 only, 5-7 feed size;
    # then three-byte mutations: a direction bit and a 15-bit offset, a xor.
    def flip(direction, at, x):
        v = (direction << 15) | at
        return bytes([v >> 8, v & 255, x])

    pm = seeds["pump"]
    pm["clean"] = bytes([0x0f])
    pm["clean-aes128"] = bytes([0x00])
    pm["clean-aes256-p384"] = bytes([0x09])
    pm["clean-chacha-p256"] = bytes([0x06])
    pm["clean-retry"] = bytes([0x1f])
    pm["clean-bytewise"] = bytes([0x2f])
    pm["clean-threes"] = bytes([0x4f])
    pm["flip-client-hello"] = bytes([0x0f]) + flip(0, 20, 1)
    pm["flip-server-hello"] = bytes([0x0f]) + flip(1, 20, 0x80)
    pm["flip-server-flight"] = bytes([0x0f]) + flip(1, 200, 1)
    pm["flip-client-finished-record"] = bytes([0x0f]) + flip(0, 260, 1)
    pm["flip-late-data"] = bytes([0x0f]) + flip(0, 400, 0x10)
    pm["flip-two"] = bytes([0x0f]) + flip(0, 20, 1) + flip(1, 300, 2)

    # The resuming pump: a first handshake, then the mutated second one.
    # Same option bits as the pump. The second ClientHello is about 330 bytes
    # of the client's stream (the offset is into the second connection), its
    # binder is the last 33, and the server's first flight is a ServerHello
    # and the encrypted EncryptedExtensions, Finished and a ticket.
    rs = seeds["resume"]
    rs["clean"] = bytes([0x0f])
    rs["clean-aes128"] = bytes([0x00])
    rs["clean-aes256-p384"] = bytes([0x09])
    rs["clean-chacha-p256"] = bytes([0x06])
    rs["clean-retry"] = bytes([0x1f])
    rs["clean-bytewise"] = bytes([0x2f])
    rs["clean-threes"] = bytes([0x4f])
    rs["flip-hello-random"] = bytes([0x0f]) + flip(0, 20, 1)
    rs["flip-hello-name"] = bytes([0x0f]) + flip(0, 80, 1)
    rs["flip-hello-ticket"] = bytes([0x0f]) + flip(0, 300, 1)
    rs["flip-hello-age"] = bytes([0x0f]) + flip(0, 420, 1)
    rs["flip-hello-binder"] = bytes([0x0f]) + flip(0, 470, 1)
    rs["flip-hello-last-byte"] = bytes([0x0f]) + flip(0, 508, 1)
    rs["flip-server-hello"] = bytes([0x0f]) + flip(1, 60, 1)
    rs["flip-server-flight"] = bytes([0x0f]) + flip(1, 120, 1)
    rs["flip-retry-hello"] = bytes([0x1f]) + flip(0, 100, 1)
    rs["flip-retry-second-hello"] = bytes([0x1f]) + flip(0, 700, 1)
    rs["flip-retry-second-binder"] = bytes([0x1f]) + flip(0, 1000, 1)
    rs["flip-two"] = bytes([0x0f]) + flip(0, 300, 1) + flip(1, 200, 2)
    # The suite of the first record the server sends (a ServerHello that selects the
    # PSK, or the retry) made the one whose hash is not the PSK's: 0x1301 to 0x1302.
    rs["flip-server-hello-suite-hash"] = bytes([0x0f]) + flip(1, 45, 0x03)
    rs["retry-names-another-hash"] = bytes([0x1f]) + flip(1, 45, 0x03)

    # The session blob and the ticket. The blob is the format in session.h:
    # version 1, the fields, the ticket and PSK, and a SHA-256 of all of it.
    def blob(suite=0x1301, psk=b"\x11" * 32, ticket=b"\x22" * 120, host=b"example.test",
             alpn=b"h2", lifetime=7200, age_add=0xa1b2c3d4, early=0, received=1700000000):
        body = bytes([1]) + struct.pack(">HIII", suite, lifetime, age_add, early)
        body += struct.pack(">q", received)
        body += bytes([len(host)]) + host + bytes([len(alpn)]) + alpn
        body += bytes([len(psk)]) + psk + struct.pack(">H", len(ticket)) + ticket
        return body + hashlib.sha256(body).digest()

    se = seeds["session"]
    good = blob()
    se["blob"] = bytes([0x70]) + good
    se["blob-sha384"] = bytes([0x70 | 4]) + blob(0x1302, psk=b"\x33" * 48)
    se["blob-no-alpn"] = bytes([0x70]) + blob(alpn=b"")
    se["blob-tight-limit"] = bytes([0x00]) + good
    se["blob-bad-digest"] = bytes([0x70]) + good[:-1] + bytes([good[-1] ^ 1])
    se["blob-wrong-version"] = bytes([0x70, 2]) + good[1:]
    se["blob-cut"] = bytes([0x70]) + good[:len(good) // 2]
    se["blob-lifetime-too-long"] = bytes([0x70]) + blob(lifetime=700000)
    se["blob-bad-psk-size"] = bytes([0x70]) + blob(psk=b"\x44" * 31)
    se["ticket-garbage"] = bytes([0x71]) + resumed["client.calculate-psk-binder.finished"]
    se["ticket-rfc"] = bytes([0x71]) + nst[17:17 + 178]   # the ticket RFC 8448 sends: not one of ours
    se["seal-sha256"] = bytes([0x72]) + bytes(range(1, 120))
    se["seal-sha384"] = bytes([0x76]) + bytes(range(1, 90))
    se["seal-chacha-empty-names"] = bytes([0x7a])
    se["blob-bigger-than-the-limit-allows"] = bytes([0x00]) + blob(ticket=b"\x22" * 700)
    se["blob-time-too-late"] = bytes([0x70]) + blob(received=2 ** 63 - 1)
    se["blob-last-time-that-fits"] = bytes([0x70]) + blob(received=2 ** 63 - 1 - 7200)
    # Tickets sealed under session_one's key (name 0x42, bytes 0x24) with a state
    # the sealer would not write: each fails a different check of the decode.
    def bad_ticket(state):
        return bytes([0x71]) + seal_ticket(0x42, 0x24, state)
    se["ticket-state-version"] = bad_ticket(ticket_state(version=3))
    se["ticket-state-v2-without-allowance"] = bad_ticket(ticket_state(version=2))
    se["ticket-state-v2-short-allowance"] = bad_ticket(ticket_state(early=7)[:55])
    se["ticket-state-unknown-suite"] = bad_ticket(ticket_state(suite=0x1234, psk_len=32))
    se["ticket-state-psk-wrong-size"] = bad_ticket(ticket_state(suite=0x1301, psk_len=48))
    se["ticket-state-short-for-sha384"] = bad_ticket(ticket_state(suite=0x1302)[:54])
    se["ticket-state-lifetime-over"] = bad_ticket(ticket_state(lifetime=604801))
    se["ticket-state-alpn-overruns"] = bad_ticket(ticket_state(alpn_len=200))
    se["ticket-state-sni-length"] = bad_ticket(ticket_state(sni_len=9))
    se["ticket-state-trailing"] = bad_ticket(ticket_state(tail=b"\x00"))
    # The freshness of a ticket from words of the input: lifetime and age_add, the
    # second it was issued, the clock, the age and the window.
    def fresh(lifetime, age_add, issued, now, age, window):
        return bytes([0x82]) + struct.pack(">IIqqII", lifetime, age_add, issued, now, age, window)
    se["fresh-ok"] = fresh(3600, 0, 0, 5, 5000, 10000)
    se["fresh-lifetime-over"] = fresh(604801, 0, 1000, 1000, 0, 10000)
    se["fresh-from-the-future"] = fresh(3600, 0, 1000000, 0, 0, 10000)
    se["fresh-age-short-of-the-clock"] = fresh(3600, 0, 0, 1000, 0, 100000000)
    se["fresh-expired"] = fresh(3600, 0, 0, 4000, 4000000, 10000)
    se["serialise"] = bytes([0x73]) + bytes(range(1, 150))
    se["serialise-sha384"] = bytes([0x77]) + bytes(range(1, 30))

    bad = 0
    for kind, files in seeds.items():
        directory = CORPUS / kind
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            path = directory / ("seed-" + name)
            if check:
                if not path.is_file() or path.read_bytes() != data:
                    print("make-fuzz-seeds: %s differs" % path.relative_to(ROOT),
                          file=sys.stderr)
                    bad = 1
            else:
                path.write_bytes(data)
    return bad


if __name__ == "__main__":
    sys.exit(main())
