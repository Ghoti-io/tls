#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io TLS.
#
# Ghoti.io TLS is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
#
# Download RFC 8448 (Example Handshake Traces for TLS 1.3) once, check it
# against the pinned SHA-256, and extract the known answers from it.
#
# The text is the source of every vector in tests/data/rfc8448. Nothing in
# those files was typed: tools/extract-rfc8448.py reads the RFC and writes
# them, and `make check-foundation` re-runs it offline against the committed
# text and fails if a committed vector differs. This script is the only step
# that needs the network, and it is only needed to re-verify the pin.
#
#   tools/fetch.sh            download, verify, extract
#   tools/fetch.sh --offline  verify and extract the committed text
#
# The SHA-256 below is of https://www.rfc-editor.org/rfc/rfc8448.txt as
# downloaded on 2026-10-06.

set -eu

PIN=6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba
URL=https://www.rfc-editor.org/rfc/rfc8448.txt

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/tests/data/rfc8448"
text="$dir/rfc8448.txt"

mkdir -p "$dir"

if [ "${1:-}" != "--offline" ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL -o "$tmp" "$URL"
  got=$(sha256sum "$tmp" | awk '{print $1}')
  if [ "$got" != "$PIN" ]; then
    echo "fetch.sh: $URL has sha256 $got, the pin says $PIN" >&2
    echo "fetch.sh: not replacing the committed text" >&2
    exit 1
  fi
  cp "$tmp" "$text"
fi

got=$(sha256sum "$text" | awk '{print $1}')
if [ "$got" != "$PIN" ]; then
  echo "fetch.sh: $text has sha256 $got, the pin says $PIN" >&2
  exit 1
fi

python3 "$root/tools/extract-rfc8448.py"
echo "fetch.sh: RFC 8448 matches its pin and the vectors are regenerated"
