import apiClient from './client'

export type OutlookMailboxParseStats = {
  raw_lines?: number
  non_empty?: number
  valid?: number
  duplicates?: number
  invalid?: number
  skipped?: number
  existing_total?: number
  saved_total?: number
  issues?: Array<{
    line?: number
    reason?: string
    email?: string
  }>
  [key: string]: unknown
}

export type RegisterProvider = {
  id?: string
  provider_id?: string
  enable?: boolean
  type?: 'yyds_mail' | 'remail' | 'outlook_token' | 'icloud_api' | string
  label?: string
  api_base?: string
  api_key?: string
  service_mode?: 'code' | 'purchase' | string
  supply?: 'private_first' | 'public_only' | string
  project_id?: number
  product_id?: number
  email_suffix?: string
  subdomain?: string | string[]
  domain?: string[]
  wildcard?: boolean
  /** Outlook credentials are write-only and are never returned by the API. */
  mailboxes?: string
  mailboxes_configured?: boolean
  mailboxes_count?: number
  mailboxes_base_count?: number
  mailboxes_alias_count?: number
  mailboxes_preview?: string[]
  alias_enabled?: boolean
  alias_per_email?: number
  alias_prefix?: string
  alias_include_original?: boolean
  mailboxes_stats?: {
    unused?: number
    in_use?: number
    used?: number
    login_required?: number
    token_invalid?: number
    failed?: number
    available?: number
    busy?: number
    retryable?: number
    invalid?: number
    abnormal?: number
    [key: string]: number | undefined
  }
  mailboxes_parse_stats?: OutlookMailboxParseStats
  mode?: 'graph' | 'imap' | 'auto' | string
  imap_host?: string
  message_limit?: number
  [key: string]: unknown
}

export type RegistrationWindowConfig = {
  time_range: string
  target_available?: number
  threads?: number
}

export type LegacyRegisterConfig = {
  mail: {
    request_timeout?: number
    wait_timeout?: number
    wait_interval?: number
    user_agent?: string
    providers?: RegisterProvider[]
    [key: string]: unknown
  }
  proxy: string
  proxy_required?: boolean
  total: number
  threads: number
  mode: 'total' | 'quota' | 'available' | string
  target_quota: number
  target_available: number
  auto_schedule_enabled: boolean
  register_peak: RegistrationWindowConfig
  register_offpeak: RegistrationWindowConfig
  check_interval: number
  enabled: boolean
  state?: 'idle' | 'running' | 'stopping' | 'paused' | string
  stats?: {
    success?: number
    fail?: number
    done?: number
    running?: number
    threads?: number
    elapsed_seconds?: number
    avg_seconds?: number
    success_rate?: number
    current_quota?: number
    current_available?: number
    pause_reason?: string
    registration_window?: 'peak' | 'offpeak' | string
    registration_time_range?: string
    target_available?: number
    [key: string]: unknown
  }
  logs?: Array<{
    time: string
    text: string
    level?: string
  }>
}

export const registerApi = {
  getConfig() {
    return apiClient.get<any, { register: LegacyRegisterConfig }>('/api/register')
  },
  updateConfig(payload: Partial<LegacyRegisterConfig>) {
    return apiClient.post<any, { register: LegacyRegisterConfig }>('/api/register', payload)
  },
  startLegacy() {
    return apiClient.post<any, { register: LegacyRegisterConfig }>('/api/register/start')
  },
  stopLegacy() {
    return apiClient.post<any, { register: LegacyRegisterConfig }>('/api/register/stop')
  },
  resetLegacy() {
    return apiClient.post<any, { register: LegacyRegisterConfig }>('/api/register/reset')
  },
  resetOutlookPool(scope: 'all' | 'retryable' | 'invalid' | 'unused' | 'failed' = 'all') {
    return apiClient.post<any, { register: LegacyRegisterConfig }>('/api/register/outlook-pool/reset', { scope })
  },
}
