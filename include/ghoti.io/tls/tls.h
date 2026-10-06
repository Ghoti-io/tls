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
 * The TLS 1.3 handshake core: handshake messages in and out (never records),
 * the key schedule, the transcript, HelloRetryRequest, and the traffic
 * secrets by epoch. Client role, server authentication only. Records, the
 * server role, client authentication, TLS 1.2, resumption and early data are
 * later pieces. See documentation/design.md.
 */

#ifndef GHOTI_IO_GTLS_TLS_H
#define GHOTI_IO_GTLS_TLS_H

#include <ghoti.io/tls/allocator.h>
#include <ghoti.io/tls/conn.h>
#include <ghoti.io/tls/context.h>
#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>
#include <ghoti.io/tls/schedule.h>
#include <ghoti.io/tls/selftest.h>

#endif /* GHOTI_IO_GTLS_TLS_H */
