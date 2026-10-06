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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GTLS_NAMESPACE_H
#define GHOTI_IO_GTLS_NAMESPACE_H

#include <ghoti.io/tls/libver.h>

/// @cond HIDDEN_SYMBOLS

/* Types. */
#define GTLS_Allocator GHOTIIO_TLS(GTLS_Allocator)
#define GTLS_Buf GHOTIIO_TLS(GTLS_Buf)
#define GTLS_CertificateMsg GHOTIIO_TLS(GTLS_CertificateMsg)
#define GTLS_CertificateVerifyMsg GHOTIIO_TLS(GTLS_CertificateVerifyMsg)
#define GTLS_ChainFn GHOTIIO_TLS(GTLS_ChainFn)
#define GTLS_ClientHello GHOTIIO_TLS(GTLS_ClientHello)
#define GTLS_Conn GHOTIIO_TLS(GTLS_Conn)
#define GTLS_Context GHOTIIO_TLS(GTLS_Context)
#define GTLS_ContextConfig GHOTIIO_TLS(GTLS_ContextConfig)
#define GTLS_Direction GHOTIIO_TLS(GTLS_Direction)
#define GTLS_EncryptedExtensions GHOTIIO_TLS(GTLS_EncryptedExtensions)
#define GTLS_Epoch GHOTIIO_TLS(GTLS_Epoch)
#define GTLS_Ext GHOTIIO_TLS(GTLS_Ext)
#define GTLS_Group GHOTIIO_TLS(GTLS_Group)
#define GTLS_Hash GHOTIIO_TLS(GTLS_Hash)
#define GTLS_HelloParams GHOTIIO_TLS(GTLS_HelloParams)
#define GTLS_KeyShare GHOTIIO_TLS(GTLS_KeyShare)
#define GTLS_Limits GHOTIIO_TLS(GTLS_Limits)
#define GTLS_NewSessionTicket GHOTIIO_TLS(GTLS_NewSessionTicket)
#define GTLS_RandomFn GHOTIIO_TLS(GTLS_RandomFn)
#define GTLS_Reader GHOTIIO_TLS(GTLS_Reader)
#define GTLS_Result GHOTIIO_TLS(GTLS_Result)
#define GTLS_Role GHOTIIO_TLS(GTLS_Role)
#define GTLS_Schedule GHOTIIO_TLS(GTLS_Schedule)
#define GTLS_SecretId GHOTIIO_TLS(GTLS_SecretId)
#define GTLS_Secrets GHOTIIO_TLS(GTLS_Secrets)
#define GTLS_ServerHello GHOTIIO_TLS(GTLS_ServerHello)
#define GTLS_State GHOTIIO_TLS(GTLS_State)
#define GTLS_Suite GHOTIIO_TLS(GTLS_Suite)
#define GTLS_Transcript GHOTIIO_TLS(GTLS_Transcript)

/* Functions, public and internal. */
#define gtls_allocator_default GHOTIIO_TLS(gtls_allocator_default)
#define gtls_buf_append GHOTIIO_TLS(gtls_buf_append)
#define gtls_buf_begin GHOTIIO_TLS(gtls_buf_begin)
#define gtls_buf_consume GHOTIIO_TLS(gtls_buf_consume)
#define gtls_buf_end GHOTIIO_TLS(gtls_buf_end)
#define gtls_buf_free GHOTIIO_TLS(gtls_buf_free)
#define gtls_buf_init GHOTIIO_TLS(gtls_buf_init)
#define gtls_buf_u16 GHOTIIO_TLS(gtls_buf_u16)
#define gtls_buf_u24 GHOTIIO_TLS(gtls_buf_u24)
#define gtls_buf_u8 GHOTIIO_TLS(gtls_buf_u8)
#define gtls_conn_alert GHOTIIO_TLS(gtls_conn_alert)
#define gtls_conn_alpn GHOTIIO_TLS(gtls_conn_alpn)
#define gtls_conn_consume_output GHOTIIO_TLS(gtls_conn_consume_output)
#define gtls_conn_debug_secret GHOTIIO_TLS(gtls_conn_debug_secret)
#define gtls_conn_debug_transcript GHOTIIO_TLS(gtls_conn_debug_transcript)
#define gtls_conn_failure GHOTIIO_TLS(gtls_conn_failure)
#define gtls_conn_feed GHOTIIO_TLS(gtls_conn_feed)
#define gtls_conn_free GHOTIIO_TLS(gtls_conn_free)
#define gtls_conn_group GHOTIIO_TLS(gtls_conn_group)
#define gtls_conn_is_connected GHOTIIO_TLS(gtls_conn_is_connected)
#define gtls_conn_is_failed GHOTIIO_TLS(gtls_conn_is_failed)
#define gtls_conn_new GHOTIIO_TLS(gtls_conn_new)
#define gtls_conn_peer_certificate GHOTIIO_TLS(gtls_conn_peer_certificate)
#define gtls_conn_pending_output GHOTIIO_TLS(gtls_conn_pending_output)
#define gtls_conn_retried GHOTIIO_TLS(gtls_conn_retried)
#define gtls_conn_secret GHOTIIO_TLS(gtls_conn_secret)
#define gtls_conn_secrets_are_wiped GHOTIIO_TLS(gtls_conn_secrets_are_wiped)
#define gtls_conn_server_name_acknowledged GHOTIIO_TLS(gtls_conn_server_name_acknowledged)
#define gtls_conn_set_hooks GHOTIIO_TLS(gtls_conn_set_hooks)
#define gtls_conn_start GHOTIIO_TLS(gtls_conn_start)
#define gtls_conn_start_raw GHOTIIO_TLS(gtls_conn_start_raw)
#define gtls_conn_state GHOTIIO_TLS(gtls_conn_state)
#define gtls_conn_suite GHOTIIO_TLS(gtls_conn_suite)
#define gtls_context_config_default GHOTIIO_TLS(gtls_context_config_default)
#define gtls_context_free GHOTIIO_TLS(gtls_context_free)
#define gtls_context_new GHOTIIO_TLS(gtls_context_new)
#define gtls_derive_secret GHOTIIO_TLS(gtls_derive_secret)
#define gtls_finished_check GHOTIIO_TLS(gtls_finished_check)
#define gtls_finished_verify_data GHOTIIO_TLS(gtls_finished_verify_data)
#define gtls_hash_len GHOTIIO_TLS(gtls_hash_len)
#define gtls_hkdf_expand_label GHOTIIO_TLS(gtls_hkdf_expand_label)
#define gtls_limits_default GHOTIIO_TLS(gtls_limits_default)
#define gtls_limits_resolve GHOTIIO_TLS(gtls_limits_resolve)
#define gtls_msg_build_client_hello GHOTIIO_TLS(gtls_msg_build_client_hello)
#define gtls_msg_downgrade_sentinel GHOTIIO_TLS(gtls_msg_downgrade_sentinel)
#define gtls_msg_extensions GHOTIIO_TLS(gtls_msg_extensions)
#define gtls_msg_find_ext GHOTIIO_TLS(gtls_msg_find_ext)
#define gtls_msg_is_hrr_random GHOTIIO_TLS(gtls_msg_is_hrr_random)
#define gtls_msg_parse_certificate GHOTIIO_TLS(gtls_msg_parse_certificate)
#define gtls_msg_parse_certificate_verify GHOTIIO_TLS(gtls_msg_parse_certificate_verify)
#define gtls_msg_parse_client_hello GHOTIIO_TLS(gtls_msg_parse_client_hello)
#define gtls_msg_parse_encrypted_extensions GHOTIIO_TLS(gtls_msg_parse_encrypted_extensions)
#define gtls_msg_parse_new_session_ticket GHOTIIO_TLS(gtls_msg_parse_new_session_ticket)
#define gtls_msg_parse_server_hello GHOTIIO_TLS(gtls_msg_parse_server_hello)
#define gtls_msg_retry_client_hello GHOTIIO_TLS(gtls_msg_retry_client_hello)
#define gtls_reader_bytes GHOTIIO_TLS(gtls_reader_bytes)
#define gtls_reader_end GHOTIIO_TLS(gtls_reader_end)
#define gtls_reader_init GHOTIIO_TLS(gtls_reader_init)
#define gtls_reader_left GHOTIIO_TLS(gtls_reader_left)
#define gtls_reader_u16 GHOTIIO_TLS(gtls_reader_u16)
#define gtls_reader_u24 GHOTIIO_TLS(gtls_reader_u24)
#define gtls_reader_u8 GHOTIIO_TLS(gtls_reader_u8)
#define gtls_reader_vector GHOTIIO_TLS(gtls_reader_vector)
#define gtls_result_string GHOTIIO_TLS(gtls_result_string)
#define gtls_schedule_early GHOTIIO_TLS(gtls_schedule_early)
#define gtls_schedule_exporter GHOTIIO_TLS(gtls_schedule_exporter)
#define gtls_schedule_handshake GHOTIIO_TLS(gtls_schedule_handshake)
#define gtls_schedule_master GHOTIIO_TLS(gtls_schedule_master)
#define gtls_schedule_resumption GHOTIIO_TLS(gtls_schedule_resumption)
#define gtls_schedule_wipe GHOTIIO_TLS(gtls_schedule_wipe)
#define gtls_selftest GHOTIIO_TLS(gtls_selftest)
#define gtls_suite_hash GHOTIIO_TLS(gtls_suite_hash)
#define gtls_suite_key_len GHOTIIO_TLS(gtls_suite_key_len)
#define gtls_suite_valid GHOTIIO_TLS(gtls_suite_valid)
#define gtls_traffic_keys GHOTIIO_TLS(gtls_traffic_keys)
#define gtls_transcript_init GHOTIIO_TLS(gtls_transcript_init)
#define gtls_transcript_restart GHOTIIO_TLS(gtls_transcript_restart)
#define gtls_transcript_select GHOTIIO_TLS(gtls_transcript_select)
#define gtls_transcript_snapshot GHOTIIO_TLS(gtls_transcript_snapshot)
#define gtls_transcript_update GHOTIIO_TLS(gtls_transcript_update)
#define gtls_transcript_wipe GHOTIIO_TLS(gtls_transcript_wipe)
#define gtls_verify_chain GHOTIIO_TLS(gtls_verify_chain)
#define gtls_version_number GHOTIIO_TLS(gtls_version_number)
#define gtls_version_string GHOTIIO_TLS(gtls_version_string)

/// @endcond

#endif // GHOTI_IO_GTLS_NAMESPACE_H
