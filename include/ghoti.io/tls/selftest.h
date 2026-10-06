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
 * @file selftest.h
 *
 * A known answer for the key schedule.
 *
 * Optional for the caller. It does not print, and it does not return the
 * bytes it used. A failure is a status from the call that failed. The
 * handshake itself has its known answers in the RFC 8448 traces under
 * tests/data/rfc8448; this checks that this build still derives the first two
 * secrets of those traces, which exercises HKDF, the label encoding and
 * SHA-256 together.
 */

#ifndef GHOTI_IO_GTLS_SELFTEST_H
#define GHOTI_IO_GTLS_SELFTEST_H

#include <ghoti.io/tls/core.h>
#include <ghoti.io/tls/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the built-in known answers.
 *
 * @return ::GTLS_OK, or the status of the first check that failed.
 */
GTLS_API GTLS_Result gtls_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GTLS_SELFTEST_H */
