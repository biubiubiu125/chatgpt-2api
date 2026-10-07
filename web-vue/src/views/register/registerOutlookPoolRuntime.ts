import type { Ref } from 'vue'
import { registerApi, type LegacyRegisterConfig } from '@/api/register'

export type OutlookResetScope = 'all' | 'retryable' | 'invalid' | 'unused'

type ConfirmOptions = {
  title: string
  message: string
  confirmText: string
}

export type RegisterOutlookPoolRuntimeInput = {
  saving: Ref<boolean>
  confirm: (options: ConfirmOptions) => Promise<boolean>
  applyConfig: (config: LegacyRegisterConfig) => void
  saveCurrentConfig?: () => Promise<void>
  notifySuccess: (message: string) => void
  notifyError: (message: string) => void
  isConfigDirty?: { value: boolean }
}

export function outlookReauthNotice(reauth: {
  replaced?: number
  failed?: number
  skipped?: number
  results?: Array<{ email?: string; status?: string; reason?: string }>
}) {
  const replaced = Number(reauth?.replaced || 0)
  const failed = Number(reauth?.failed || 0)
  const skipped = Number(reauth?.skipped || 0)
  const details = (reauth?.results || [])
    .filter(item => item?.status !== 'replaced' && String(item?.reason || '').trim())
    .map(item => `${String(item.email || '邮箱').trim() || '邮箱'}：${String(item.reason).trim()}`)
  const shown = details.slice(0, 3)
  if (details.length > shown.length) shown.push(`另有 ${details.length - shown.length} 条`)
  return {
    level: failed > 0 ? 'error' as const : 'success' as const,
    message: [`重授权完成：更换 ${replaced}，失败 ${failed}，跳过 ${skipped}`, ...shown].join('；'),
  }
}

export const outlookPoolActionItems = [
  { key: 'retry_failed', label: '重试临时失败' },
  { key: 'retryable', label: '释放占用/失败' },
  { key: 'invalid', label: '清除异常标记', dividerBefore: true },
  { key: 'reauthorize', label: '用辅助邮箱重授权' },
  { key: 'unused', label: '清掉未使用的邮箱', danger: true, dividerBefore: true },
  { key: 'all', label: '重置全部邮箱池', danger: true },
]

const resetCopy: Record<OutlookResetScope, ConfirmOptions> = {
  retryable: {
    title: '释放占用/临时失败',
    message: '将释放 in_use 和 failed 邮箱，后续注册任务可以重新使用这些材料。',
    confirmText: '释放',
  },
  invalid: {
    title: '清除异常标记',
    message: '将清除 token_invalid、login_required 和连续收不到验证码后的停用标记，但不会修复失效的 refresh_token，也不会交还已经提交过的加号标签。',
    confirmText: '清除',
  },
  unused: {
    title: '清掉未使用的邮箱',
    message: '将移除没有使用记录的 Outlook 邮箱行。已提交过加号标签或已停用的主号会保留，refresh_token 不会被删掉。',
    confirmText: '清掉',
  },
  all: {
    title: '重置全部邮箱池',
    message: '将重置占用、失败、已用和停用状态。已经提交给注册平台的加号标签会保留，不会重新放回。',
    confirmText: '重置',
  },
}

export function useRegisterOutlookPoolRuntime(input: RegisterOutlookPoolRuntimeInput) {
  function hasUnsavedEdits() {
    return Boolean(input.isConfigDirty?.value)
  }

  function refuseUnsaved(action: string) {
    if (!hasUnsavedEdits()) return false
    input.notifyError(`页面有未保存的修改，请先保存再${action}`)
    return true
  }

  function keepUnsavedEdits() {
    if (!hasUnsavedEdits()) return false
    input.notifyError('维护期间页面被修改，没有覆盖未保存内容。请先刷新，不要把旧内容保存回去。')
    return true
  }

  async function resetPool(scope: OutlookResetScope) {
    const copy = resetCopy[scope]
    if (refuseUnsaved(copy.title)) return
    const ok = await input.confirm(copy)
    if (!ok || refuseUnsaved(copy.title)) return
    input.saving.value = true
    try {
      const response = await registerApi.resetOutlookPool(scope)
      if (keepUnsavedEdits()) return
      input.applyConfig(response.register)
      input.notifySuccess('邮箱池状态已更新')
    } catch (error: any) {
      input.notifyError(error?.message || '邮箱池维护失败')
    } finally {
      input.saving.value = false
    }
  }

  async function retryFailedPool() {
    const ok = await input.confirm({
      title: '重试临时失败邮箱',
      message: '将释放 in_use 和 failed 邮箱，并立即启动注册任务继续重试。',
      confirmText: '重试',
    })
    if (!ok) return
    try {
      await input.saveCurrentConfig?.()
      if (hasUnsavedEdits()) return
      input.saving.value = true
      const resetResponse = await registerApi.resetOutlookPool('retryable')
      if (keepUnsavedEdits()) return
      input.applyConfig(resetResponse.register)
      const startResponse = await registerApi.startLegacy()
      if (keepUnsavedEdits()) return
      input.applyConfig(startResponse.register)
      input.notifySuccess('已释放临时失败邮箱并启动注册任务')
    } catch (error: any) {
      input.notifyError(error?.message || '重试临时失败邮箱失败')
    } finally {
      input.saving.value = false
    }
  }

  async function reauthorizePool() {
    if (refuseUnsaved('用辅助邮箱重授权')) return
    const ok = await input.confirm({
      title: '用辅助邮箱重授权',
      message: '只处理失效或需登录、并且带了辅助邮箱的行。注册任务运行时不能执行。成功后只更换主令牌，不改注册收信邮箱。页面有未保存修改时请先保存。',
      confirmText: '重授权',
    })
    if (!ok || refuseUnsaved('用辅助邮箱重授权')) return
    input.saving.value = true
    try {
      const response = await registerApi.reauthorizeOutlookPool()
      if (keepUnsavedEdits()) return
      input.applyConfig(response.register)
      const notice = outlookReauthNotice(response.reauth)
      if (notice.level === 'error') input.notifyError(notice.message)
      else input.notifySuccess(notice.message)
    } catch (error: any) {
      input.notifyError(error?.message || '辅助邮箱重授权失败')
    } finally {
      input.saving.value = false
    }
  }

  function handleAction(key: string) {
    if (key === 'retry_failed') return retryFailedPool()
    if (key === 'reauthorize') return reauthorizePool()
    if (key === 'retryable' || key === 'invalid' || key === 'unused' || key === 'all') return resetPool(key)
  }

  return {
    outlookPoolActionItems,
    resetPool,
    retryFailedPool,
    handleAction,
  }
}
