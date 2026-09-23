import { parseProxyReference, serializeProxyReference } from '@/api/proxy'
import type { LegacyRegisterConfig, RegisterProvider } from '@/api/register'
import { CHROME146_USER_AGENT } from '@/lib/browserFingerprint'

export type RegisterMode = 'total' | 'quota' | 'available'
export type RuntimeLogLevel = 'info' | 'success' | 'warning' | 'error'

export type RegisterMetricItem = {
  key: string
  label: string
  value: string | number
  meta?: string
}

export type RegisterRuntimeLogLine = {
  key: string
  time: string
  text: string
  level: RuntimeLogLevel
}

export const providerTypeOptions = [
  { value: 'yyds_mail', label: 'YYDS Mail' },
  { value: 'remail', label: 'Remail' },
  { value: 'outlook_token', label: 'Outlook Token' },
  { value: 'icloud_api', label: 'iCloud API' },
]
export const allowedProviderTypes = providerTypeOptions.map(option => option.value)

export const providerTypeGroups = [{ options: providerTypeOptions }]

export const registerModeOptions = [
  { value: 'total', label: '按数量注册' },
  { value: 'quota', label: '达到额度停止' },
  { value: 'available', label: '达到账号数停止' },
] as const

export const registerModeGroups = [{ options: registerModeOptions }]

export const registerProxyHint = '注册必须使用住宅代理，不能用默认出口或代理组。'

export const remailServiceModeOptions = [
  { value: 'code', label: 'code 短效接码' },
  { value: 'purchase', label: 'purchase 长效邮箱' },
] as const

export const remailServiceModeGroups = [{ options: remailServiceModeOptions }]

export const remailSupplyOptions = [
  { value: 'private_first', label: 'private_first' },
  { value: 'public_only', label: 'public_only' },
] as const

export const remailSupplyGroups = [{ options: remailSupplyOptions }]

export const outlookModeOptions = [
  { value: 'graph', label: 'Graph API' },
  { value: 'imap', label: 'IMAP' },
  { value: 'auto', label: '自动兜底' },
] as const

export const outlookModeGroups = [{ options: outlookModeOptions }]

export const providerCommonKeys = ['id', 'enable', 'type', 'label'] as const
export const providerSecretPlaceholder = '********'
export const providerSecretKeys = ['api_key'] as const
export const providerMailUserAgentChrome146 = CHROME146_USER_AGENT

export const providerTypeKeys: Record<string, string[]> = {
  yyds_mail: ['api_base', 'api_key', 'domain', 'subdomain', 'wildcard'],
  remail: ['api_base', 'api_key', 'service_mode', 'supply', 'project_id', 'product_id', 'email_suffix'],
  outlook_token: ['mailboxes', 'mode', 'imap_host', 'message_limit', 'alias_enabled', 'alias_per_email', 'alias_prefix', 'alias_include_original'],
  icloud_api: ['api_base', 'api_key'],
}

export const providerLocalOnlyKeys: Record<string, string[]> = {
  outlook_token: ['mailboxes_configured', 'mailboxes_count', 'mailboxes_base_count', 'mailboxes_alias_count', 'mailboxes_preview', 'mailboxes_stats', 'mailboxes_parse_stats'],
}

export const defaultRegisterConfig: LegacyRegisterConfig = {
  mail: {
    request_timeout: 30,
    wait_timeout: 30,
    wait_interval: 2,
    user_agent: providerMailUserAgentChrome146,
    providers: [],
  },
  proxy: '',
  proxy_required: true,
  total: 10,
  threads: 2,
  mode: 'available',
  target_quota: 100,
  target_available: 30,
  auto_schedule_enabled: true,
  register_peak: {
    time_range: '09:00-18:00',
    target_available: 100,
    threads: 4,
  },
  register_offpeak: {
    time_range: '18:00-09:00',
    target_available: 30,
    threads: 2,
  },
  check_interval: 5,
  enabled: false,
  state: 'idle',
  stats: {
    success: 0,
    fail: 0,
    done: 0,
    running: 0,
    threads: 2,
    elapsed_seconds: 0,
    avg_seconds: 0,
    success_rate: 0,
    current_quota: 0,
    current_available: 0,
  },
  logs: [],
}

export function normalizeProviderType(type: unknown) {
  const value = String(type || 'yyds_mail').trim().toLowerCase()
  return allowedProviderTypes.includes(value) ? value : 'yyds_mail'
}

export function providerType(provider: RegisterProvider) {
  return normalizeProviderType(provider.type)
}

export function createProviderId(type = 'provider') {
  const suffix = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '').slice(0, 12)
    : Math.random().toString(36).slice(2, 14).padEnd(12, '0')
  return `${type}-${suffix}`
}

export function defaultProvider(type = 'yyds_mail'): RegisterProvider {
  const normalizedType = normalizeProviderType(type)
  const base = { id: createProviderId(normalizedType), enable: true, type: normalizedType }
  switch (normalizedType) {
    case 'yyds_mail':
      return { ...base, api_base: 'https://maliapi.215.im/v1', api_key: '', domain: [], subdomain: '', wildcard: false }
    case 'remail':
      return {
        ...base,
        api_base: 'https://remail.aishop6.com',
        api_key: '',
        service_mode: 'code',
        supply: 'private_first',
        project_id: 2,
        product_id: 5,
        email_suffix: '',
      }
    case 'outlook_token':
      return {
        ...base,
        mailboxes: '',
        mode: 'auto',
        imap_host: 'outlook.office365.com',
        message_limit: 10,
        alias_enabled: false,
        alias_per_email: 5,
        alias_prefix: 'c2api',
        alias_include_original: true,
      }
    case 'icloud_api':
      return { ...base, api_base: '', api_key: '' }
    default:
      return base
  }
}

export function normalizeProvider(provider: RegisterProvider): RegisterProvider {
  const type = providerType(provider)
  return {
    ...defaultProvider(type),
    ...provider,
    id: String(provider.id || provider.provider_id || '').trim() || createProviderId(type),
    type,
    enable: provider.enable !== false,
  }
}

export function normalizeRegisterConfig(raw: LegacyRegisterConfig): LegacyRegisterConfig {
  const mail = {
    ...defaultRegisterConfig.mail,
    ...(raw.mail || {}),
    providers: Array.isArray(raw.mail?.providers)
      ? raw.mail.providers
        .filter(item => allowedProviderTypes.includes(String(item?.type || '').trim().toLowerCase()))
        .map(item => normalizeProvider(item))
      : [],
  }
  mail.user_agent = chrome146UserAgent(mail.user_agent)
  if (!mail.providers.length) {
    mail.providers = [defaultProvider('yyds_mail')]
  }
  const rawConfig = { ...raw } as LegacyRegisterConfig & { max_inflight_per_proxy?: number }
  delete rawConfig.max_inflight_per_proxy
  return {
    ...defaultRegisterConfig,
    ...rawConfig,
    threads: Math.min(16, Math.max(1, Number(raw.threads) || defaultRegisterConfig.threads)),
    proxy: normalizeRegisterProxyValue(raw.proxy),
    proxy_required: true,
    mail,
    register_peak: {
      ...defaultRegisterConfig.register_peak,
      ...(raw.register_peak || {}),
      target_available: Math.max(1, Number(raw.register_peak?.target_available) || defaultRegisterConfig.register_peak.target_available || 1),
      threads: Math.min(16, Math.max(1, Number(raw.register_peak?.threads) || defaultRegisterConfig.register_peak.threads || 1)),
    },
    register_offpeak: {
      ...defaultRegisterConfig.register_offpeak,
      ...(raw.register_offpeak || {}),
      target_available: Math.max(1, Number(raw.register_offpeak?.target_available) || defaultRegisterConfig.register_offpeak.target_available || 1),
      threads: Math.min(16, Math.max(1, Number(raw.register_offpeak?.threads) || defaultRegisterConfig.register_offpeak.threads || 1)),
    },
    stats: { ...defaultRegisterConfig.stats, ...(raw.stats || {}) },
    logs: Array.isArray(raw.logs) ? raw.logs : [],
  }
}

export function providerTitle(_provider: RegisterProvider, index: number) {
  return `邮箱来源 ${index + 1}`
}

export function providerTypeLabel(type: string) {
  return providerTypeOptions.find(item => item.value === type)?.label || type
}

const registerProxySchemes = new Set(['http', 'https', 'socks', 'socks5', 'socks5h'])
const registerProxyReferences = new Set(['', 'direct', 'global'])

function coerceRegisterProxyInput(value: string): string {
  const raw = value.trim()
  if (!raw || raw.includes('://')) return raw
  const parts = raw.split(':')
  if (parts.length === 2 && /^\d+$/.test(parts[1] || '')) return `http://${raw}`
  if (parts.length === 4 && /^\d+$/.test(parts[1] || '')) {
    return `http://${encodeURIComponent(parts[2] || '')}:${encodeURIComponent(parts[3] || '')}@${parts[0]}:${parts[1]}`
  }
  return raw
}

export function isRegisterProxyUrl(value: unknown): boolean {
  const raw = String(value || '').trim()
  const lower = raw.toLowerCase()
  if (!raw || registerProxyReferences.has(lower) || lower.startsWith('group:') || lower.startsWith('profile:')) {
    return false
  }
  try {
    const parsed = new URL(coerceRegisterProxyInput(raw))
    const scheme = parsed.protocol.replace(/:$/, '').toLowerCase()
    return registerProxySchemes.has(scheme) && Boolean(parsed.host)
  } catch {
    return false
  }
}

export function normalizeRegisterProxyValue(value: unknown): string {
  const reference = parseProxyReference(value)
  if (reference.mode !== 'custom') return ''
  const raw = serializeProxyReference('custom', reference.value)
  if (!isRegisterProxyUrl(raw)) return ''
  return coerceRegisterProxyInput(raw)
}

export function providerKeysForType(type: string, includeLocalOnly = false) {
  const normalizedType = normalizeProviderType(type)
  return [
    ...providerCommonKeys,
    ...(providerTypeKeys[normalizedType] || []),
    ...(includeLocalOnly ? providerLocalOnlyKeys[normalizedType] || [] : []),
  ]
}

export function providerHasKnownType(type: string) {
  return Object.prototype.hasOwnProperty.call(providerTypeKeys, normalizeProviderType(type))
}

export function isFilled(value: unknown) {
  return String(value ?? '').trim().length > 0
}

export function listHasValue(value: unknown) {
  if (Array.isArray(value)) return value.some(item => isFilled(item))
  return isFilled(value)
}

function isPositiveInteger(value: unknown) {
  if (!isFilled(value)) return false
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0
}

export function listFromProviderDraft(value: unknown) {
  if (Array.isArray(value)) return value.map(String).map(item => item.trim()).filter(Boolean)
  return String(value || '')
    .split(/[\n,]/)
    .map(item => item.trim())
    .filter(Boolean)
}

export function providerDraftValue(type: string, key: string, value: unknown) {
  const normalizedType = normalizeProviderType(type)
  if (key === 'domain') return listFromProviderDraft(value)
  if (key === 'subdomain' && normalizedType === 'yyds_mail') {
    return Array.isArray(value) ? value.join('\n') : String(value || '')
  }
  return value
}

export function providerWithTypeDraft(current: RegisterProvider, type: string): RegisterProvider {
  const normalizedType = normalizeProviderType(type)
  const defaults = defaultProvider(normalizedType)
  const currentType = providerType(current)
  const typeChanged = currentType !== normalizedType
  const next: RegisterProvider = {
    ...current,
    ...defaults,
    id: String(current.id || current.provider_id || defaults.id || '').trim(),
    type: normalizedType,
    enable: current.enable !== false,
  }

  for (const key of providerKeysForType(normalizedType, true)) {
    if (key === 'type' || key === 'enable') continue
    if (current[key] !== undefined) {
      if (typeChanged && providerSecretKeys.includes(key as typeof providerSecretKeys[number])) {
        next[key] = defaults[key]
        continue
      }
      if (typeChanged && normalizedType === 'remail' && key === 'api_base') {
        next[key] = defaults[key]
        continue
      }
      next[key] = providerDraftValue(normalizedType, key, current[key])
    }
  }

  next.type = normalizedType
  next.enable = current.enable !== false

  return next
}

export function sanitizedProviderPayload(provider: RegisterProvider): RegisterProvider {
  const type = providerType(provider)
  const output: RegisterProvider = {}

  for (const key of providerKeysForType(type)) {
    if (provider[key] !== undefined) {
      output[key] = providerDraftValue(type, key, provider[key])
    }
  }

  delete output.mailboxes_count
  delete output.mailboxes_base_count
  delete output.mailboxes_alias_count
  delete output.mailboxes_preview
  delete output.mailboxes_stats
  delete output.mailboxes_parse_stats
  delete output.provider_ref
  return output
}

export function legacyRegisterPayload(config: LegacyRegisterConfig): Partial<LegacyRegisterConfig> {
  return {
    mail: {
      ...config.mail,
      api_use_register_proxy: false,
      user_agent: chrome146UserAgent(config.mail.user_agent),
      providers: (config.mail.providers || []).map(sanitizedProviderPayload),
    },
    proxy: normalizeRegisterProxyValue(config.proxy),
    proxy_required: true,
    total: Math.max(1, Number(config.total) || 1),
    threads: Math.min(16, Math.max(1, Number(config.threads) || 1)),
    mode: (config.mode || 'total') as RegisterMode,
    target_quota: Math.max(1, Number(config.target_quota) || 1),
    target_available: Math.max(1, Number(config.target_available) || 1),
    auto_schedule_enabled: Boolean(config.auto_schedule_enabled),
    register_peak: {
      time_range: String(config.register_peak.time_range || '09:00-18:00').trim(),
      target_available: Math.max(1, Number(config.register_peak.target_available) || 1),
      threads: Math.min(16, Math.max(1, Number(config.register_peak.threads) || 1)),
    },
    register_offpeak: {
      time_range: String(config.register_offpeak.time_range || '18:00-09:00').trim(),
      target_available: Math.max(1, Number(config.register_offpeak.target_available) || 1),
      threads: Math.min(16, Math.max(1, Number(config.register_offpeak.threads) || 1)),
    },
    check_interval: Math.max(1, Number(config.check_interval) || 5),
  }
}

export function pendingOutlookCount(provider: RegisterProvider) {
  return String(provider.mailboxes || '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && line.split('----').length >= 4)
    .length
}

export function providerRequirementMessages(provider: RegisterProvider) {
  const type = providerType(provider)
  const missing: string[] = []
  const requireValue = (value: unknown, label: string) => {
    if (!isFilled(value)) missing.push(label)
  }
  const requirePositiveInteger = (value: unknown, label: string) => {
    if (!isPositiveInteger(value)) missing.push(label)
  }

  switch (type) {
    case 'yyds_mail':
      requireValue(provider.api_key, 'API Key')
      break
    case 'icloud_api':
      requireValue(provider.api_base, '服务地址')
      requireValue(provider.api_key, 'API Key')
      break
    case 'remail':
      requireValue(provider.api_base, 'API Base')
      requireValue(provider.api_key, 'API Key')
      requirePositiveInteger(provider.project_id, 'Project ID')
      requirePositiveInteger(provider.product_id, 'Product ID')
      break
    case 'outlook_token': {
      const savedCount = Number(provider.mailboxes_count || 0)
      if (savedCount <= 0 && pendingOutlookCount(provider) <= 0) missing.push('Microsoft 邮箱凭据池')
      break
    }
    default:
      break
  }

  return missing
}

export function providerUsesApiBase(provider: RegisterProvider) {
  return ['yyds_mail', 'icloud_api', 'remail'].includes(providerType(provider))
}

function chrome146UserAgent(value: unknown) {
  void value
  return providerMailUserAgentChrome146
}

export function providerUsesApiKey(provider: RegisterProvider) {
  return ['yyds_mail', 'icloud_api', 'remail'].includes(providerType(provider))
}

export function providerUsesDomainList(provider: RegisterProvider) {
  return providerType(provider) === 'yyds_mail'
}

export function apiBaseLabel(provider: RegisterProvider) {
  return providerType(provider) === 'icloud_api' ? '服务地址' : 'API Base'
}

export function apiBasePlaceholder(provider: RegisterProvider) {
  const type = providerType(provider)
  if (type === 'yyds_mail') return 'https://maliapi.215.im/v1'
  if (type === 'icloud_api') return 'https://mail.example.com'
  if (type === 'remail') return 'https://remail.aishop6.com'
  return ''
}

export function domainLabel(_provider: RegisterProvider) {
  return '域名'
}

export function domainPlaceholder(_provider: RegisterProvider) {
  return '每行一个域名，可留空'
}

export function numeric(value: unknown) {
  return Number(value || 0) || 0
}

export function outlookPoolSummary(provider: RegisterProvider) {
  const stats = provider.mailboxes_stats || {}
  const inUse = numeric(stats.in_use)
  const loginRequired = numeric(stats.login_required)
  const tokenInvalid = numeric(stats.token_invalid)
  const failed = numeric(stats.failed)
  const retryable = numeric(stats.retryable) || failed
  const invalid = numeric(stats.invalid) || loginRequired + tokenInvalid

  return {
    saved: numeric(provider.mailboxes_count),
    pending: pendingOutlookCount(provider),
    available: numeric(stats.available) || numeric(stats.unused),
    used: numeric(stats.used),
    inUse,
    loginRequired,
    tokenInvalid,
    failed,
    retryable,
    invalid,
    abnormal: retryable + invalid,
  }
}

export function outlookAliasSummary(provider: RegisterProvider) {
  const base = numeric(provider.mailboxes_base_count || provider.mailboxes_count)
  const alias = numeric(provider.mailboxes_alias_count)
  const perEmail = numeric(provider.alias_per_email)
  const includeOriginal = provider.alias_include_original !== false
  const multiplier = provider.alias_enabled ? perEmail + (includeOriginal ? 1 : 0) : 1
  const pending = pendingOutlookCount(provider)
  return {
    enabled: Boolean(provider.alias_enabled),
    base,
    alias,
    perEmail,
    includeOriginal,
    multiplier,
    pending,
    pendingExpanded: provider.alias_enabled ? pending * multiplier : pending,
  }
}

export function outlookAliasHint(provider: RegisterProvider) {
  const summary = outlookAliasSummary(provider)
  if (!summary.enabled) return '未启用加号别名，注册时直接使用导入邮箱。'
  if (summary.pending > 0) {
    return `保存后本次导入约展开为 ${summary.pendingExpanded} 个注册地址；登录和收信仍使用原邮箱凭据。`
  }
  if (summary.base > 0) {
    return `已保存 ${summary.base} 个原邮箱，当前规则生成 ${summary.alias} 个别名地址；登录和收信仍使用原邮箱凭据。`
  }
  return '保存后会为 Outlook / Hotmail 地址生成加号别名；登录和收信仍使用原邮箱凭据。'
}

export function outlookPoolHint(provider: RegisterProvider) {
  const summary = outlookPoolSummary(provider)
  if (summary.pending > 0) return `有 ${summary.pending} 个待保存，保存配置后进入 Microsoft 邮箱池。`
  if (summary.saved <= 0) return '还没有保存 Microsoft 邮箱材料。'
  if (summary.invalid > 0) return `有 ${summary.invalid} 个异常邮箱，需要重新获取 refresh_token 或重新导入材料。`
  if (summary.retryable > 0 || summary.inUse > 0) return `有 ${summary.retryable} 个临时失败、${summary.inUse} 个占用，可在更多维护里释放后重试。`
  if (summary.available <= 0) return '库存已用完，请导入新的 Microsoft 邮箱材料。'
  return `已保存 ${summary.saved} 个 Microsoft 邮箱材料。`
}

export function formatClock(value?: string | null) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleTimeString()
}

export function arrayText(value: unknown) {
  if (Array.isArray(value)) return value.map(String).join('\n')
  return String(value || '')
}

export function registerMetricItems(
  stats: NonNullable<LegacyRegisterConfig['stats']>,
  threads = 0,
): RegisterMetricItem[] {
  return [
    { key: 'success', label: '成功', value: stats.success || 0, meta: `成功率 ${stats.success_rate || 0}%` },
    { key: 'fail', label: '失败', value: stats.fail || 0 },
    { key: 'done', label: '完成', value: stats.done || 0 },
    { key: 'running', label: '运行 / 线程', value: `${stats.running || 0} / ${stats.threads || threads || 0}` },
    { key: 'elapsed', label: '运行时间', value: `${stats.elapsed_seconds || 0}s` },
    { key: 'avg', label: '平均耗时', value: `${stats.avg_seconds || 0}s` },
    { key: 'quota', label: '当前额度', value: stats.current_quota || 0 },
    { key: 'available', label: '正常账号', value: stats.current_available || 0 },
  ]
}

export function enabledRegisterProviderCount(providers: readonly RegisterProvider[]) {
  return providers.filter(provider => provider.enable !== false).length
}

export function registerProviderIssueCount(providers: readonly RegisterProvider[]) {
  return providers
    .filter(provider => provider.enable !== false)
    .reduce((total, provider) => total + providerRequirementMessages(provider).length, 0)
}

export function registerActionDisabled(
  config: LegacyRegisterConfig | null | undefined,
  legacySaving: boolean,
  enabledCount: number,
  issueCount: number,
) {
  if (legacySaving || !config) return true
  if (registerTaskState(config) === 'stopping') return true
  if (config.enabled) return false
  if (!normalizeRegisterProxyValue(config.proxy)) return true
  return enabledCount === 0 || issueCount > 0
}

export function registerTaskState(config: LegacyRegisterConfig | null | undefined) {
  const state = String(config?.state || '').trim().toLowerCase()
  if (state) return state
  return config?.enabled ? 'running' : 'idle'
}

export function registerStateText(config: LegacyRegisterConfig | null | undefined) {
  const state = registerTaskState(config)
  if (state === 'running') return '运行中'
  if (state === 'stopping') return '停止中'
  if (state === 'paused') return '已暂停'
  return config?.enabled ? '已开启' : '未启动'
}

export function registerStateTone(config: LegacyRegisterConfig | null | undefined): 'success' | 'warning' | 'muted' {
  const state = registerTaskState(config)
  if (state === 'running') return 'success'
  if (state === 'stopping') return 'warning'
  if (state === 'paused') return 'muted'
  return 'muted'
}

export function registerRuntimeHint(
  config: LegacyRegisterConfig | null | undefined,
  enabledCount: number,
  issueCount: number,
) {
  if (enabledCount === 0) return '至少启用一个邮箱来源。'
  if (issueCount > 0) return `还有 ${issueCount} 项必填配置未完成。`
  if (!normalizeRegisterProxyValue(config?.proxy)) return '请填写住宅代理后再启动。'
  if (registerTaskState(config) === 'stopping') return '任务正在停止，等待当前运行任务结束。'
  if (registerTaskState(config) === 'paused') return '任务已开启但未实际运行，通常是注册代理或账号池暂不可用。'
  if (config?.enabled) return '任务运行中，配置已锁定。'
  return '启动前会自动保存当前配置。'
}

export function registerRuntimeLogLines(
  logs: NonNullable<LegacyRegisterConfig['logs']>,
  format: (value?: string | null) => string = formatClock,
): RegisterRuntimeLogLine[] {
  return logs.slice().reverse().map((item, index) => ({
    key: registerRuntimeLogLineKey(item, logs.length - index - 1),
    time: format(item.time),
    text: item.text || '-',
    level: normalizeRuntimeLogLevel(item.level),
  }))
}

function registerRuntimeLogLineKey(
  item: NonNullable<LegacyRegisterConfig['logs']>[number],
  sourceIndex: number,
): string {
  const time = String(item.time || 'log').replaceAll('|', '/')
  const level = String(item.level || 'info').replaceAll('|', '/')
  const text = String(item.text || '-').replaceAll('|', '/')
  const sample = text.length <= 96 ? text : `${text.length}:${text.slice(0, 72)}:${text.slice(-16)}`
  return `${time}|${level}|${sample}|${sourceIndex}`
}

export function normalizeRuntimeLogLevel(level?: string): RuntimeLogLevel {
  if (level === 'red' || level === 'error') return 'error'
  if (level === 'green' || level === 'success') return 'success'
  if (level === 'yellow' || level === 'warning') return 'warning'
  return 'info'
}
