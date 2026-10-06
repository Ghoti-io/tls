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
 * @file core_internal.h
 *
 * Private declarations shared by the library's modules.
 */

#ifndef GHOTI_IO_GTLS_SRC_CORE_CORE_INTERNAL_H
#define GHOTI_IO_GTLS_SRC_CORE_CORE_INTERNAL_H

#include <ghoti.io/tls/macros.h>

#include <ghoti.io/tls/core.h>
#include <ghoti.io/security/security.h>

#include <stddef.h>
#include <stdint.h>

/**
 * Turn a limits pointer the caller may have left NULL, or half-filled with
 * zeros, into a struct every field of which is a real cap.
 */
void gtls_limits_resolve(const GTLS_Limits * in, GTLS_Limits * out);

/**
 * Map a primitive's status into this library's. A switch with an internal
 * error as its default, not a cast: the two enums happen to share numbers
 * today and a cast would go on compiling after they stopped.
 */
static inline GTLS_Result gtls_from_gsec(GSEC_Result result) {
  switch (result) {
    case GSEC_OK:
      return GTLS_OK;
    case GSEC_ERR_IO:
      return GTLS_ERR_IO;
    case GSEC_ERR_FORMAT:
      return GTLS_ERR_FORMAT;
    case GSEC_ERR_UNSUPPORTED:
      return GTLS_ERR_UNSUPPORTED;
    case GSEC_ERR_LIMIT:
      return GTLS_ERR_LIMIT;
    case GSEC_ERR_CORRUPT:
      return GTLS_ERR_CORRUPT;
    case GSEC_ERR_OOM:
      return GTLS_ERR_OOM;
    case GSEC_ERR_INVALID:
      return GTLS_ERR_INVALID;
    case GSEC_ERR_INTERNAL:
      return GTLS_ERR_INTERNAL;
    case GSEC_ERR_MISMATCH:
      return GTLS_ERR_MISMATCH;
    case GSEC_RESULT_COUNT:
      break;
  }
  return GTLS_ERR_INTERNAL;
}

#endif /* GHOTI_IO_GTLS_SRC_CORE_CORE_INTERNAL_H */
