/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io TLS.
 *
 * Ghoti.io TLS is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io TLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file tls.h
 *
 * Umbrella header for the Ghoti.io TLS library.
 *
 * TLS 1.3 as a state machine over buffers: the handshake in both roles (the
 * client authenticates the server; the server presents an identity chosen by
 * SNI, selects ALPN, and retries with a HelloRetryRequest), the key schedule,
 * the traffic secrets by epoch for a caller that carries messages itself
 * (QUIC), and the record layer over a byte stream with key update,
 * close_notify and a truncation check for a caller that carries a stream.
 * Session tickets and PSK resumption are built, in both roles (session.h);
 * early data (0-RTT, with the replay decision left to the caller) is built in
 * both roles (record.h); client authentication and TLS 1.2 are later pieces.
 * See documentation/design.md.
 */

#ifndef GHOTI_IO_GTLS_TLS_H
#define GHOTI_IO_GTLS_TLS_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/conn.h>
#include <ghoti.io/tls/context.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/record.h>
#include <ghoti.io/tls/schedule.h>
#include <ghoti.io/tls/selftest.h>
#include <ghoti.io/tls/session.h>

#endif /* GHOTI_IO_GTLS_TLS_H */
