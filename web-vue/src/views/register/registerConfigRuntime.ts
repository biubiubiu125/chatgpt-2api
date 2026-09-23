import { computed, ref, watch } from 'vue'
import { getAuthToken } from '@/api/client'
import { registerApi, type LegacyRegisterConfig } from '@/api/register'
import { usePageQuery } from '@/composables/usePageQuery'
import type { PageRuntime } from '@/composables/usePageRuntime'
import {
  legacyRegisterPayload,
  normalizeRegisterConfig,
  normalizeRegisterProxyValue,
} from '@/views/register/registerProviderView'

type ConfirmOptions = {
  title?: string
  message: string
  confirmText?: string
  cancelText?: string
}

export type RegisterConfigRuntimeInput = {
  runtime: PageRuntime
  confirm: (options: ConfirmOptions) => Promise<boolean>
  notifySuccess: (message: string) => void
  notifyError: (message: string) => void
  startLiveUpdates?: () => void
}

const REGISTER_CONFIG_REQUEST_KEY = 'register:config'

export function useRegisterConfigRuntime(input: RegisterConfigRuntimeInput) {
  const loading = ref(false)
  const saving = ref(false)
  const customProxyInput = ref('')
  const config = ref<LegacyRegisterConfig | null>(null)
  const isConfigDirty = ref(false)
  const lastAppliedConfigSignature = ref('')
  const applyListeners = new Set<() => void>()

  const configQuery = usePageQuery({
    runtime: input.runtime,
    key: REGISTER_CONFIG_REQUEST_KEY,
    loading,
    errorMessage: '加载注册配置失败',
  })

  const providers = computed(() => config.value?.mail.providers || [])

  function onConfigApplied(callback: () => void) {
    applyListeners.add(callback)
    return () => applyListeners.delete(callback)
  }

  function syncProxyControlsFromValue(value: unknown) {
    customProxyInput.value = normalizeRegisterProxyValue(value)
  }

  function configSignature(value: LegacyRegisterConfig | null) {
    if (!value) return ''
    try {
      return JSON.stringify(legacyRegisterPayload(value))
    } catch {
      return ''
    }
  }

  function applyConfig(nextConfig: LegacyRegisterConfig, resetDirty = true) {
    const normalized = normalizeRegisterConfig(nextConfig)
    config.value = normalized
    syncProxyControlsFromValue(config.value.proxy)
    lastAppliedConfigSignature.value = configSignature(config.value)
    if (resetDirty) isConfigDirty.value = false
    applyListeners.forEach((callback) => callback())
  }

  function applyRemoteConfig(nextConfig: LegacyRegisterConfig) {
    if (isConfigDirty.value) return false
    applyConfig(nextConfig)
    return true
  }

  watch(config, (value) => {
    if (!value) {
      isConfigDirty.value = false
      lastAppliedConfigSignature.value = ''
      return
    }
    const signature = configSignature(value)
    isConfigDirty.value = Boolean(signature && signature !== lastAppliedConfigSignature.value)
  }, { deep: true })

  function setCustomProxyInput(value: string) {
    customProxyInput.value = String(value || '').trim()
    if (config.value) {
      config.value.proxy = normalizeRegisterProxyValue(customProxyInput.value)
      config.value.proxy_required = true
    }
  }

  function payload(): Partial<LegacyRegisterConfig> {
    if (!config.value) return {}
    return legacyRegisterPayload({
      ...config.value,
      proxy: normalizeRegisterProxyValue(customProxyInput.value || config.value.proxy),
      proxy_required: true,
      mail: {
        ...config.value.mail,
        providers: providers.value,
      },
    })
  }

  async function loadConfig(silent = false) {
    await configQuery.run(
      () => registerApi.getConfig(),
      {
        apply: (response) => {
          if (silent && isConfigDirty.value) return
          applyConfig(response.register)
        },
        onError: (message) => {
          if (!silent) input.notifyError(message)
        },
        silentLoading: silent,
      },
    )
  }

  async function saveConfig() {
    if (!config.value) return
    saving.value = true
    try {
      const response = await registerApi.updateConfig(payload())
      applyConfig(response.register)
      input.notifySuccess('注册配置已保存')
    } catch (error: any) {
      input.notifyError(error?.message || '保存注册配置失败')
    } finally {
      saving.value = false
    }
  }

  async function toggleTask() {
    if (!config.value) return
    const starting = !config.value.enabled
    const ok = await input.confirm({
      title: starting ? '启动注册任务' : '停止注册任务',
      message: starting ? '将保存当前配置并启动注册任务。' : '将停止当前注册任务。',
      confirmText: starting ? '启动' : '停止',
    })
    if (!ok) return
    saving.value = true
    try {
      if (starting) {
        await registerApi.updateConfig(payload())
      }
      const response = starting ? await registerApi.startLegacy() : await registerApi.stopLegacy()
      applyConfig(response.register)
      if (starting) {
        const state = String(response.register?.state || '')
        const pauseReason = String((response.register?.stats || {}).pause_reason || '')
        input.notifySuccess(
          state === 'running'
            ? '\u6ce8\u518c\u4efb\u52a1\u5df2\u542f\u52a8'
            : `\u6ce8\u518c\u4efb\u52a1\u5df2\u5f00\u542f\uff0c\u5f53\u524d\u5904\u4e8e${pauseReason || state || '\u7b49\u5f85'}\u72b6\u6001`,
        )
      } else {
        input.notifySuccess('\u6ce8\u518c\u4efb\u52a1\u5df2\u505c\u6b62')
      }
      if (starting) input.startLiveUpdates?.()
    } catch (error: any) {
      input.notifyError(error?.message || '切换注册任务失败')
    } finally {
      saving.value = false
    }
  }

  async function resetStats() {
    const ok = await input.confirm({
      title: '重置注册统计',
      message: '将清空当前注册任务的统计和运行日志。',
      confirmText: '重置',
    })
    if (!ok) return
    saving.value = true
    try {
      const response = await registerApi.resetLegacy()
      applyConfig(response.register)
      input.notifySuccess('注册统计已重置')
    } catch (error: any) {
      input.notifyError(error?.message || '重置注册统计失败')
    } finally {
      saving.value = false
    }
  }

  function invalidate() {
    configQuery.invalidate()
  }

  function isTaskEnabled() {
    return Boolean(config.value?.enabled)
  }

  return {
    authToken: getAuthToken,
    loading,
    saving,
    customProxyInput,
    config,
    isConfigDirty,
    providers,
    applyConfig,
    applyRemoteConfig,
    onConfigApplied,
    setCustomProxyInput,
    payload,
    loadConfig,
    saveConfig,
    toggleTask,
    resetStats,
    invalidate,
    isTaskEnabled,
  }
}
