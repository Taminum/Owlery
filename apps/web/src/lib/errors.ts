import { ApiError } from './api'
import { t, type MsgKey } from '../i18n'

/** Turns any error into a localized sentence. Server messages are never shown raw. */
export function errorText(err: unknown): string {
  if (err instanceof ApiError) return codeText(err.code)
  return t('err.unknown')
}

export function codeText(code: string | undefined): string {
  if (!code) return t('err.unknown')
  const key = `err.${code}` as MsgKey
  try {
    const text = t(key)
    return text ?? t('err.unknown')
  } catch {
    return t('err.unknown')
  }
}

const KNOWN = new Set<string>([
  'invalid_url', 'unsafe_target', 'dns_failure', 'connect_failed', 'tls_failure', 'timeout', 'redirect_blocked', 'response_too_large',
  'request_failed', 'unauthorized', 'missing_permission', 'endpoint_not_found', 'rate_limited', 'upstream_error', 'incompatible_api',
  'unexpected_status', 'credential_unreadable', 'forbidden', 'not_found', 'name_taken', 'sync_in_progress', 'panel_disabled', 'demo_panel',
  'network', 'internal', 'invalid_settings', 'invalid_name', 'invalid_token', 'custom_ca_unavailable', 'probe_failed', 'partial_capabilities',
  'confirmation_mismatch', 'retention_required', 'username_taken', 'weak_password', 'invalid_username', 'invalid_memberships',
  'cannot_disable_self', 'invalid_credentials', 'cross_origin', 'csrf',
])

export const hasErrorText = (code: string | undefined): boolean => !!code && KNOWN.has(code)
