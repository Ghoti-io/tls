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
"""

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
    seeds = {"client": {}, "msg": {}, "server": {}, "stream": {}, "record": {}, "pump": {}}

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
