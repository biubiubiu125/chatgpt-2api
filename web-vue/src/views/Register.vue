<template>
  <div
    class="register-page"
    :class="{ 'lg:flex lg:min-h-0 lg:flex-1 lg:flex-col': isWorkspaceLayout }"
  >
    <PagePanel
      class="space-y-4"
      :class="{ 'min-h-0 flex-1 overflow-y-auto': isWorkspaceLayout }"
    >
      <PanelHeader title="注册账号" align="start">
        <template #actions>
          <StateBadge :tone="registerStateTone" shape="rounded" size="sm">
            {{ registerStateText }}
          </StateBadge>
          <Button
            size="sm"
            variant="primary"
            :disabled="legacySaving || !registerConfig || registerTaskLocked"
            @click="saveLegacyConfig"
          >
            保存配置
          </Button>
        </template>
      </PanelHeader>

      <PageLoadingState
        v-if="legacyLoading && !registerConfig"
        title="正在加载注册配置"
        description="读取邮箱来源、任务参数和运行状态。"
      />

      <div v-else-if="registerConfig" class="register-layout">
        <div class="register-config-column">
          <RegisterTaskSettingsPanel
            :config="registerConfig"
            :custom-proxy-input="customRegisterProxyInput"
            @update-custom-proxy="setCustomRegisterProxyInput"
          />

          <FormSection title="邮箱来源" density="roomy">
            <template #actions>
              <MetaChip v-if="enabledProviderIssueCount" size="xs" tone="danger">
                缺失 {{ enabledProviderIssueCount }}
              </MetaChip>
              <MetaChip size="xs" tone="muted">已启用 {{ enabledProviderCount }} / {{ registerProviders.length }}</MetaChip>
              <Button
                size="sm"
                variant="outline"
                :disabled="registerTaskLocked"
                @click="addProvider"
              >
                添加来源
              </Button>
            </template>

            <div class="register-provider-list">
              <RegisterProviderCard
                v-for="(provider, index) in registerProviders"
                :key="providerKey(provider, index)"
                :provider="provider"
                :index="index"
                :provider-count="registerProviders.length"
                :disabled="registerTaskLocked"
                :saving="legacySaving"
                :outlook-pool-action-items="outlookPoolActionItems"
                @update-type="updateProviderType"
                @update-field="updateProviderField"
                @update-array="updateProviderArray"
                @delete="deleteProvider"
                @outlook-action="handleOutlookPoolAction"
              />
            </div>
          </FormSection>
        </div>

        <RegisterRuntimePanel
          :enabled="registerConfig.enabled"
          :state="registerTaskState"
          :saving="legacySaving"
          :action-disabled="registerActionDisabled"
          :runtime-hint="registerRuntimeHint"
          :metric-items="registerMetricItems"
          :runtime-log-lines="runtimeLogLines"
          @toggle-task="toggleLegacyTask"
          @reset-stats="resetLegacyStats"
        />
      </div>
    </PagePanel>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Button } from 'nanocat-ui'
import FormSection from '@/components/ai/FormSection.vue'
import MetaChip from '@/components/ai/MetaChip.vue'
import PageLoadingState from '@/components/ai/PageLoadingState.vue'
import PagePanel from '@/components/ai/PagePanel.vue'
import PanelHeader from '@/components/ai/PanelHeader.vue'
import StateBadge from '@/components/ai/StateBadge.vue'
import { useConfirmDialog } from '@/composables/useConfirmDialog'
import { useListLayoutPreference } from '@/composables/useListLayoutPreference'
import { usePageRuntime } from '@/composables/usePageRuntime'
import { useToast } from '@/composables/useToast'
import RegisterProviderCard from '@/views/register/RegisterProviderCard.vue'
import RegisterRuntimePanel from '@/views/register/RegisterRuntimePanel.vue'
import RegisterTaskSettingsPanel from '@/views/register/RegisterTaskSettingsPanel.vue'
import {
  defaultRegisterConfig,
  enabledRegisterProviderCount as buildEnabledRegisterProviderCount,
  formatClock,
  registerActionDisabled as buildRegisterActionDisabled,
  registerMetricItems as buildRegisterMetricItems,
  registerProviderIssueCount as buildRegisterProviderIssueCount,
  registerRuntimeHint as buildRegisterRuntimeHint,
  registerRuntimeLogLines as buildRegisterRuntimeLogLines,
  registerStateText as buildRegisterStateText,
  registerStateTone as buildRegisterStateTone,
  registerTaskState as buildRegisterTaskState,
} from '@/views/register/registerProviderView'
import { useRegisterConfigRuntime } from '@/views/register/registerConfigRuntime'
import { useRegisterLiveRuntime } from '@/views/register/registerLiveRuntime'
import { useRegisterOutlookPoolRuntime } from '@/views/register/registerOutlookPoolRuntime'
import { useRegisterProviderRuntime } from '@/views/register/registerProviderRuntime'

defineOptions({ name: 'Register' })

const toast = useToast()
const confirmDialog = useConfirmDialog()
const pageRuntime = usePageRuntime('register')
const { isWorkspaceLayout } = useListLayoutPreference()

const registerConfigRuntime = useRegisterConfigRuntime({
  runtime: pageRuntime,
  confirm: confirmDialog.ask,
  notifySuccess: (message) => toast.success(message),
  notifyError: (message) => toast.error(message),
  startLiveUpdates: () => startLiveUpdates(),
})
const legacyLoading = registerConfigRuntime.loading
const legacySaving = registerConfigRuntime.saving
const registerConfig = registerConfigRuntime.config
const registerProviders = registerConfigRuntime.providers
const customRegisterProxyInput = registerConfigRuntime.customProxyInput
const applyRegisterConfig = registerConfigRuntime.applyConfig
const applyRemoteRegisterConfig = registerConfigRuntime.applyRemoteConfig
const loadRegisterConfig = registerConfigRuntime.loadConfig
const saveLegacyConfig = registerConfigRuntime.saveConfig
const toggleLegacyTask = registerConfigRuntime.toggleTask
const resetLegacyStats = registerConfigRuntime.resetStats
const setCustomRegisterProxyInput = registerConfigRuntime.setCustomProxyInput
const outlookPoolRuntime = useRegisterOutlookPoolRuntime({
  saving: legacySaving,
  confirm: confirmDialog.ask,
  applyConfig: (config) => applyRegisterConfig(config),
  saveCurrentConfig: () => saveLegacyConfig(),
  notifySuccess: (message) => toast.success(message),
  notifyError: (message) => toast.error(message),
})
const outlookPoolActionItems = outlookPoolRuntime.outlookPoolActionItems
const handleOutlookPoolAction = outlookPoolRuntime.handleAction
const liveRuntime = useRegisterLiveRuntime({
  runtime: pageRuntime,
  getAuthToken: registerConfigRuntime.authToken,
  loadConfig: (silent) => loadRegisterConfig(silent),
  applyRemoteConfig: (config) => applyRemoteRegisterConfig(config),
  isTaskEnabled: registerConfigRuntime.isTaskEnabled,
})
const startLiveUpdates = liveRuntime.startLiveUpdates
const enabledProviderCount = computed(() => buildEnabledRegisterProviderCount(registerProviders.value))
const enabledProviderIssueCount = computed(() => buildRegisterProviderIssueCount(registerProviders.value))
const registerTaskState = computed(() => buildRegisterTaskState(registerConfig.value))
const registerTaskLocked = computed(() => ['running', 'stopping'].includes(registerTaskState.value))
const registerStateText = computed(() => buildRegisterStateText(registerConfig.value))
const registerStateTone = computed(() => buildRegisterStateTone(registerConfig.value))
const registerActionDisabled = computed(() => buildRegisterActionDisabled(
  registerConfig.value,
  legacySaving.value,
  enabledProviderCount.value,
  enabledProviderIssueCount.value,
))
const legacyStats = computed(() => ({ ...defaultRegisterConfig.stats, ...(registerConfig.value?.stats || {}) }))
const legacyLogs = computed(() => [...(registerConfig.value?.logs || [])])
const registerRuntimeHint = computed(() => buildRegisterRuntimeHint(
  registerConfig.value,
  enabledProviderCount.value,
  enabledProviderIssueCount.value,
))

const registerMetricItems = computed(() => buildRegisterMetricItems(legacyStats.value, registerConfig.value?.threads || 0))

const runtimeLogLines = computed(() => buildRegisterRuntimeLogLines(legacyLogs.value, formatClock))
const providerRuntime = useRegisterProviderRuntime({
  config: registerConfig,
  providers: registerProviders,
  confirm: confirmDialog.ask,
})
const providerKey = providerRuntime.providerKey
const updateProviderType = providerRuntime.updateProviderType
const updateProviderField = providerRuntime.updateProviderField
const addProvider = providerRuntime.addProvider
const deleteProvider = providerRuntime.deleteProvider
const updateProviderArray = providerRuntime.updateProviderArray

function activateRegisterView(refresh = false) {
  if (refresh) {
    void loadRegisterConfig(true)
  }
  startLiveUpdates()
}

function deactivateRegisterView() {
  registerConfigRuntime.invalidate()
  liveRuntime.stop()
}

pageRuntime.onActivate(({ initial }) => {
  if (initial) {
    void (async () => {
      await loadRegisterConfig()
      startLiveUpdates()
    })()
    return
  }
  activateRegisterView(true)
})

pageRuntime.onDeactivate(() => {
  deactivateRegisterView()
})

pageRuntime.onHide(() => {
  deactivateRegisterView()
})

pageRuntime.onShow(() => {
  void loadRegisterConfig(true)
  startLiveUpdates()
})
</script>

<style scoped>
.register-layout {
  display: grid;
  gap: 18px;
}

@media (min-width: 1280px) {
  .register-layout {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    align-items: start;
  }
}

.register-config-column {
  min-width: 0;
}

.register-config-column {
  display: grid;
  gap: 16px;
}

.register-provider-list {
  display: grid;
  gap: 14px;
}

</style>
