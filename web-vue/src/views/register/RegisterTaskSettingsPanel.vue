<template>
  <div class="register-task-settings">
    <FormSection title="任务参数" density="roomy">
      <div class="register-form-grid">
        <label class="register-checkbox-field register-field--full">
          <Checkbox v-model="config.auto_schedule_enabled" :disabled="config.enabled">
            按时段自动补号
          </Checkbox>
        </label>

        <template v-if="config.auto_schedule_enabled">
          <label class="register-field">
            <span class="register-label">高峰时段</span>
            <Input
              v-model.trim="config.register_peak.time_range"
              block
              root-class="font-mono"
              placeholder="18:00-02:00"
              :disabled="config.enabled"
            />
          </label>

          <label class="register-field">
            <span class="register-label">高峰目标账号</span>
            <Input
              v-model.number="config.register_peak.target_available"
              type="number"
              min="1"
              block
              :disabled="config.enabled"
            />
          </label>

          <label class="register-field">
            <span class="register-label">高峰线程数</span>
            <Input
              v-model.number="config.register_peak.threads"
              type="number"
              min="1"
              max="16"
              block
              :disabled="config.enabled"
            />
          </label>

          <label class="register-field">
            <span class="register-label">普通时段</span>
            <Input
              v-model.trim="config.register_offpeak.time_range"
              block
              root-class="font-mono"
              placeholder="02:00-18:00"
              :disabled="config.enabled"
            />
          </label>

          <label class="register-field">
            <span class="register-label">普通目标账号</span>
            <Input
              v-model.number="config.register_offpeak.target_available"
              type="number"
              min="1"
              block
              :disabled="config.enabled"
            />
          </label>
          <label class="register-field">
            <span class="register-label">普通线程数</span>
            <Input
              v-model.number="config.register_offpeak.threads"
              type="number"
              min="1"
              max="16"
              block
              :disabled="config.enabled"
            />
          </label>
        </template>

        <label v-if="!config.auto_schedule_enabled" class="register-field">
          <span class="register-label">任务模式</span>
          <GroupedSelectMenu
            v-model="config.mode"
            :groups="registerModeGroups"
            selected-indicator="none"
            :disabled="config.enabled"
            block
          />
        </label>

        <label v-if="!config.auto_schedule_enabled && config.mode === 'total'" class="register-field">
          <span class="register-label">注册总数</span>
          <Input
            v-model.number="config.total"
            type="number"
            min="1"
            block
            :disabled="config.enabled || config.mode !== 'total'"
          />
        </label>

        <label v-else-if="!config.auto_schedule_enabled && config.mode === 'quota'" class="register-field">
          <span class="register-label">目标剩余额度</span>
          <Input
            v-model.number="config.target_quota"
            type="number"
            min="1"
            block
            :disabled="config.enabled"
          />
        </label>

        <label v-else-if="!config.auto_schedule_enabled" class="register-field">
          <span class="register-label">目标可用账号</span>
          <Input
            v-model.number="config.target_available"
            type="number"
            min="1"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field">
          <span class="register-label">线程数</span>
          <Input
            v-model.number="config.threads"
            type="number"
            min="1"
            max="16"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field">
          <span class="register-label">检查间隔（秒）</span>
          <Input
            v-model.number="config.check_interval"
            type="number"
            min="1"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field register-field--full">
          <span class="register-label">注册代理</span>
          <Input
            :model-value="customProxyInput"
            block
            root-class="font-mono"
            placeholder="socks5://user:pass@host:port"
            :disabled="config.enabled"
            @update:model-value="emit('update-custom-proxy', $event)"
          />
        </label>

        <p class="register-proxy-hint register-field--full">
          注册必须使用住宅代理，不能用默认出口或代理组。
        </p>
      </div>
    </FormSection>

    <FormSection title="邮箱请求" density="roomy">
      <div class="register-form-grid register-form-grid--mail">
        <label class="register-field">
          <span class="register-label">请求超时（秒）</span>
          <Input
            v-model.number="config.mail.request_timeout"
            type="number"
            min="1"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field">
          <span class="register-label">验证码等待（秒）</span>
          <Input
            v-model.number="config.mail.wait_timeout"
            type="number"
            min="1"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field">
          <span class="register-label">轮询间隔（秒）</span>
          <Input
            v-model.number="config.mail.wait_interval"
            type="number"
            min="1"
            step="0.2"
            block
            :disabled="config.enabled"
          />
        </label>

        <label class="register-field register-field--full">
          <span class="register-label">请求 User-Agent</span>
          <Input
            :model-value="providerMailUserAgentChrome146"
            block
            root-class="font-mono"
            disabled
          />
        </label>
      </div>
    </FormSection>
  </div>
</template>

<script setup lang="ts">
import { Checkbox, Input } from 'nanocat-ui'

import FormSection from '@/components/ai/FormSection.vue'
import GroupedSelectMenu from '@/components/ui/GroupedSelectMenu.vue'
import type { LegacyRegisterConfig } from '@/api/register'
import {
  providerMailUserAgentChrome146,
  registerModeGroups,
} from '@/views/register/registerProviderView'

defineProps<{
  config: LegacyRegisterConfig
  customProxyInput: string
}>()

const emit = defineEmits<{
  (e: 'update-custom-proxy', value: string): void
}>()
</script>

<style scoped>
.register-task-settings {
  display: grid;
  gap: 16px;
}

.register-form-grid {
  display: grid;
  gap: 12px;
}

@media (min-width: 720px) {
  .register-form-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .register-field--full {
    grid-column: 1 / -1;
  }

  .register-form-grid--mail {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

.register-field {
  display: grid;
  min-width: 0;
  gap: 7px;
}

.register-label {
  font-size: 12px;
  color: hsl(var(--muted-foreground));
}

.register-checkbox-field {
  display: flex;
  min-height: 34px;
  align-items: center;
}

.register-proxy-hint {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: hsl(var(--muted-foreground));
}
</style>
