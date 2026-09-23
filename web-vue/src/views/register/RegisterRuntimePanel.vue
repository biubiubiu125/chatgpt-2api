<template>
  <aside class="register-runtime-column">
    <FormSection title="执行控制" density="roomy" class="register-runtime-section">
      <MetricStrip
        :items="metricItems"
        columns-class="grid-cols-2 md:grid-cols-4"
        density="compact"
      />

      <div class="register-runtime-actions">
        <Button
          block
          variant="primary"
          :disabled="actionDisabled"
          @click="emit('toggle-task')"
        >
          {{ enabled ? '停止' : '启动' }}
        </Button>
        <Button
          block
          variant="outline"
          :disabled="resetDisabled"
          @click="emit('reset-stats')"
        >
          重置
        </Button>
      </div>

      <SurfaceBox tone="muted" density="compact">
        {{ runtimeHint }}
      </SurfaceBox>

      <SurfaceBox tone="muted" density="compact" class="register-runtime-tips">
        <p>Cloudflare 拦截：在系统设置用手动 Cookie 填写 Chrome146 的 cf_clearance，不要使用 FlareSolverr。</p>
        <p>HTTP 400 等注册错误通常与邮箱域名风控有关，建议更换新的域名邮箱后重试。</p>
      </SurfaceBox>
    </FormSection>

    <RuntimeLogPanel
      class="register-runtime-log"
      title="实时日志"
      :lines="runtimeLogLines"
      :empty-title="'暂无日志'"
      min-height="20rem"
      max-height="min(58vh, 38rem)"
    />
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Button } from 'nanocat-ui'

import FormSection from '@/components/ai/FormSection.vue'
import MetricStrip from '@/components/ai/MetricStrip.vue'
import RuntimeLogPanel from '@/components/ai/RuntimeLogPanel.vue'
import SurfaceBox from '@/components/ai/SurfaceBox.vue'
import type { RegisterMetricItem, RegisterRuntimeLogLine } from '@/views/register/registerProviderView'

const props = defineProps<{
  enabled: boolean
  state: string
  saving: boolean
  actionDisabled: boolean
  runtimeHint: string
  metricItems: RegisterMetricItem[]
  runtimeLogLines: RegisterRuntimeLogLine[]
}>()

const emit = defineEmits<{
  (e: 'toggle-task'): void
  (e: 'reset-stats'): void
}>()

const resetDisabled = computed(() => props.saving || props.enabled || props.state !== 'idle')
</script>

<style scoped>
.register-runtime-column {
  display: grid;
  min-width: 0;
  gap: 16px;
  position: sticky;
  top: 16px;
}

.register-runtime-section {
  display: grid;
  gap: 12px;
}

.register-runtime-log {
  min-width: 0;
}

.register-runtime-tips {
  display: grid;
  gap: 4px;
  color: hsl(var(--muted-foreground));
  line-height: 1.6;
}

.register-runtime-tips p {
  margin: 0;
}

.register-runtime-actions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

@media (max-width: 1279px) {
  .register-runtime-column {
    position: static;
  }
}

@media (max-width: 640px) {
  .register-runtime-actions {
    grid-template-columns: 1fr;
    justify-content: flex-start;
  }

  .register-runtime-actions {
    display: grid;
  }
}
</style>
