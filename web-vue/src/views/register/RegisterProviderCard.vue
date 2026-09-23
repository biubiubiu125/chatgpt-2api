<template>
  <FormSection
    class="register-provider-card"
    surface="background"
    density="normal"
  >
    <div class="register-provider-head">
      <div class="min-w-0">
        <div class="register-provider-title">
          <span>{{ providerTitle(provider, index) }}</span>
          <MetaChip size="xs" tone="muted">{{ providerTypeLabel(currentType) }}</MetaChip>
          <MetaChip v-if="provider.enable === false" size="xs" tone="warning">未启用</MetaChip>
          <MetaChip v-else-if="requirementMessages.length" size="xs" tone="danger">
            缺失 {{ requirementMessages.length }} 项
          </MetaChip>
          <MetaChip v-else size="xs" tone="success">可用</MetaChip>
        </div>
      </div>
      <div class="register-provider-actions">
        <Checkbox
          :model-value="provider.enable !== false"
          :disabled="disabled"
          @update:model-value="value => emit('update-field', index, 'enable', Boolean(value))"
        >
          启用
        </Checkbox>
        <Button
          size="sm"
          variant="ghost"
          :disabled="disabled || providerCount <= 1"
          @click="emit('delete', index)"
        >
          删除
        </Button>
      </div>
    </div>

    <SurfaceBox
      v-if="provider.enable !== false && requirementMessages.length"
      class="register-provider-message"
      tone="danger"
      density="compact"
    >
      缺少：{{ requirementMessages.join('、') }}
    </SurfaceBox>

    <div class="register-provider-section">
      <div class="register-provider-section-title">基础配置</div>
      <div class="register-form-grid register-form-grid--two">
        <label class="register-field">
          <span class="register-label">类型</span>
          <GroupedSelectMenu
            :model-value="provider.type || 'yyds_mail'"
            :groups="providerTypeGroups"
            selected-indicator="none"
            :disabled="disabled"
            block
            @update:model-value="value => emit('update-type', index, String(value))"
          />
        </label>

        <label v-if="providerUsesApiBase(provider)" class="register-field">
          <span class="register-label">{{ apiBaseLabel(provider) }}</span>
          <Input
            :model-value="provider.api_base"
            block
            root-class="font-mono"
            :disabled="disabled"
            :placeholder="apiBasePlaceholder(provider)"
            @update:model-value="value => emit('update-field', index, 'api_base', String(value || '').trim())"
          />
        </label>

        <label v-if="providerUsesApiKey(provider)" class="register-field">
          <span class="register-label">API Key</span>
          <Input
            :model-value="provider.api_key"
            block
            root-class="font-mono"
            :disabled="disabled"
            @update:model-value="value => emit('update-field', index, 'api_key', String(value || '').trim())"
          />
        </label>

        <label v-if="currentType === 'remail'" class="register-field">
          <span class="register-label">接码模式</span>
          <GroupedSelectMenu
            :model-value="provider.service_mode || 'code'"
            :groups="remailServiceModeGroups"
            selected-indicator="none"
            :disabled="disabled"
            block
            @update:model-value="value => emit('update-field', index, 'service_mode', value)"
          />
        </label>

        <label v-if="currentType === 'remail'" class="register-field">
          <span class="register-label">供应策略</span>
          <GroupedSelectMenu
            :model-value="provider.supply || 'private_first'"
            :groups="remailSupplyGroups"
            selected-indicator="none"
            :disabled="disabled"
            block
            @update:model-value="value => emit('update-field', index, 'supply', value)"
          />
        </label>

        <label v-if="currentType === 'remail'" class="register-field">
          <span class="register-label">Project ID</span>
          <Input
            :model-value="provider.project_id"
            type="number"
            min="1"
            block
            :disabled="disabled"
            @update:model-value="value => emit('update-field', index, 'project_id', numberModelValue(value))"
          />
        </label>

        <label v-if="currentType === 'remail'" class="register-field">
          <span class="register-label">Product ID</span>
          <Input
            :model-value="provider.product_id"
            type="number"
            min="1"
            block
            :disabled="disabled"
            @update:model-value="value => emit('update-field', index, 'product_id', numberModelValue(value))"
          />
        </label>

        <label v-if="currentType === 'remail'" class="register-field">
          <span class="register-label">邮箱后缀（可选）</span>
          <Input
            :model-value="provider.email_suffix"
            block
            :disabled="disabled"
            placeholder="outlook.com，可选"
            @update:model-value="value => emit('update-field', index, 'email_suffix', String(value || '').trim())"
          />
        </label>

        <label v-if="currentType === 'yyds_mail'" class="register-field">
          <span class="register-label">Subdomain</span>
          <Input
            :model-value="arrayText(provider.subdomain)"
            block
            :disabled="disabled"
            placeholder="可留空"
            @update:model-value="value => emit('update-field', index, 'subdomain', String(value || ''))"
          />
        </label>

        <label v-if="currentType === 'yyds_mail'" class="register-checkbox-field">
          <Checkbox
            :model-value="provider.wildcard"
            :disabled="disabled"
            @update:model-value="value => emit('update-field', index, 'wildcard', Boolean(value))"
          >
            Wildcard
          </Checkbox>
        </label>
      </div>
    </div>

    <div
      v-if="providerUsesDomainList(provider)"
      class="register-provider-section"
    >
      <div class="register-provider-section-title">域名配置</div>
      <div class="register-provider-stack">
        <label class="register-field">
          <span class="register-label">{{ domainLabel(provider) }}</span>
          <textarea
            class="register-textarea"
            :disabled="disabled"
            :placeholder="domainPlaceholder(provider)"
            :value="arrayText(provider.domain)"
            @input="emit('update-array', index, 'domain', ($event.target as HTMLTextAreaElement).value)"
          ></textarea>
        </label>
      </div>
    </div>

    <div v-if="currentType === 'outlook_token'" class="register-provider-section register-provider-section--soft">
      <div class="register-provider-section-title">Outlook 邮箱池</div>

      <div class="register-form-grid register-form-grid--three">
        <label class="register-field">
          <span class="register-label">读取方式</span>
          <GroupedSelectMenu
            :model-value="provider.mode"
            :groups="outlookModeGroups"
            selected-indicator="none"
            :disabled="disabled"
            block
            @update:model-value="value => emit('update-field', index, 'mode', value)"
          />
        </label>

        <label v-if="provider.mode !== 'graph'" class="register-field">
          <span class="register-label">IMAP Host</span>
          <Input
            :model-value="provider.imap_host"
            block
            root-class="font-mono"
            :disabled="disabled"
            placeholder="outlook.office365.com"
            @update:model-value="value => emit('update-field', index, 'imap_host', String(value || '').trim())"
          />
        </label>

        <label class="register-field">
          <span class="register-label">读取邮件数</span>
          <Input
            :model-value="provider.message_limit"
            type="number"
            min="1"
            block
            :disabled="disabled"
            @update:model-value="value => emit('update-field', index, 'message_limit', numberModelValue(value))"
          />
        </label>
      </div>

      <div class="register-provider-section register-provider-section--soft">
        <div class="register-provider-section-title">加号别名</div>
        <div class="register-form-grid register-form-grid--three">
          <label class="register-checkbox-field register-checkbox-field--compact register-field--full">
            <Checkbox
              :model-value="provider.alias_enabled"
              :disabled="disabled"
              @update:model-value="value => emit('update-field', index, 'alias_enabled', Boolean(value))"
            >
              启用 Outlook / Hotmail 加号别名
            </Checkbox>
          </label>

          <label class="register-field">
            <span class="register-label">每个邮箱别名数</span>
            <Input
              :model-value="provider.alias_per_email"
              type="number"
              min="0"
              max="200"
              block
              :disabled="disabled || !provider.alias_enabled"
              @update:model-value="value => emit('update-field', index, 'alias_per_email', numberModelValue(value))"
            />
          </label>

          <label class="register-field">
            <span class="register-label">别名前缀</span>
            <Input
              :model-value="provider.alias_prefix"
              block
              root-class="font-mono"
              placeholder="c2api"
              :disabled="disabled || !provider.alias_enabled"
              @update:model-value="value => emit('update-field', index, 'alias_prefix', String(value || '').trim())"
            />
          </label>

          <label class="register-checkbox-field register-checkbox-field--compact">
            <Checkbox
              :model-value="provider.alias_include_original"
              :disabled="disabled || !provider.alias_enabled"
              @update:model-value="value => emit('update-field', index, 'alias_include_original', Boolean(value))"
            >
              包含原邮箱
            </Checkbox>
          </label>
        </div>
        <p class="register-preview-line">{{ outlookAliasHint(provider) }}</p>
      </div>

      <label class="register-field">
        <span class="register-label">邮箱池（完整列表）</span>
        <textarea
          class="register-textarea register-textarea--tall"
          :disabled="disabled"
          :value="String(provider.mailboxes || '')"
          placeholder="每行：邮箱----密码----client_id----refresh_token。留空保存则不修改整池"
          @input="emit('update-field', index, 'mailboxes', ($event.target as HTMLTextAreaElement).value)"
        ></textarea>
      </label>
      <p class="register-preview-line">提交的是完整邮箱池。删除一行后保存会从池中移除该邮箱；某行密码留空则沿用已保存密码。</p>

      <div class="register-outlook-toolbar">
        <div class="register-outlook-summary">
          <MetaChip size="xs" tone="success">可用 {{ outlookSummary.available }}</MetaChip>
          <MetaChip size="xs" tone="muted">占用 {{ outlookSummary.inUse }}</MetaChip>
          <MetaChip size="xs" tone="muted">已用 {{ outlookSummary.used }}</MetaChip>
          <MetaChip size="xs" :tone="outlookSummary.retryable ? 'warning' : 'muted'">
            临时失败 {{ outlookSummary.retryable }}
          </MetaChip>
          <MetaChip size="xs" :tone="outlookSummary.invalid ? 'danger' : 'muted'">
            异常 {{ outlookSummary.invalid }}
          </MetaChip>
          <MetaChip v-if="outlookSummary.pending" size="xs" tone="info">
            待保存 {{ outlookSummary.pending }}
          </MetaChip>
        </div>

        <FloatingActionMenu
          label="更多维护"
          :items="outlookPoolActionItems"
          :disabled="disabled || saving"
          align="right"
          placement="auto"
          :trigger-min-width="96"
          @select="key => emit('outlook-action', key)"
        />
      </div>

      <p class="register-preview-line">{{ outlookPoolHint(provider) }}</p>
      <details class="register-outlook-details">
        <summary>邮箱池详情</summary>
        <div class="register-outlook-detail-chips">
          <MetaChip size="xs" tone="muted">已保存 {{ outlookSummary.saved }}</MetaChip>
          <MetaChip size="xs" tone="info">待保存 {{ outlookSummary.pending }}</MetaChip>
          <MetaChip size="xs" tone="muted">占用 {{ outlookSummary.inUse }}</MetaChip>
          <MetaChip size="xs" tone="warning">需登录 {{ outlookSummary.loginRequired }}</MetaChip>
          <MetaChip size="xs" tone="warning">失效 {{ outlookSummary.tokenInvalid }}</MetaChip>
          <MetaChip size="xs" tone="warning">临时失败 {{ outlookSummary.failed }}</MetaChip>
        </div>
      </details>
    </div>
  </FormSection>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Button, Checkbox, Input } from 'nanocat-ui'
import type { ActionMenuItem } from 'nanocat-ui'

import type { RegisterProvider } from '@/api/register'
import FloatingActionMenu from '@/components/ai/FloatingActionMenu.vue'
import FormSection from '@/components/ai/FormSection.vue'
import MetaChip from '@/components/ai/MetaChip.vue'
import SurfaceBox from '@/components/ai/SurfaceBox.vue'
import GroupedSelectMenu from '@/components/ui/GroupedSelectMenu.vue'
import {
  apiBaseLabel,
  apiBasePlaceholder,
  arrayText,
  domainLabel,
  domainPlaceholder,
  outlookAliasHint,
  outlookModeGroups,
  outlookPoolHint,
  outlookPoolSummary,
  providerRequirementMessages,
  remailServiceModeGroups,
  remailSupplyGroups,
  providerTitle,
  providerType,
  providerTypeGroups,
  providerTypeLabel,
  providerUsesApiBase,
  providerUsesApiKey,
  providerUsesDomainList,
} from '@/views/register/registerProviderView'

type ProviderArrayKey = 'domain'

const props = defineProps<{
  provider: RegisterProvider
  index: number
  providerCount: number
  disabled: boolean
  saving: boolean
  outlookPoolActionItems: ActionMenuItem[]
}>()

const emit = defineEmits<{
  (e: 'update-type', index: number, type: string): void
  (e: 'update-field', index: number, key: string, value: unknown): void
  (e: 'update-array', index: number, key: ProviderArrayKey, value: string): void
  (e: 'delete', index: number): void
  (e: 'outlook-action', key: string): void
}>()

const currentType = computed(() => providerType(props.provider))
const requirementMessages = computed(() => providerRequirementMessages(props.provider))
const outlookSummary = computed(() => outlookPoolSummary(props.provider))

function numberModelValue(value: unknown) {
  const parsed = Number.parseFloat(String(value))
  return Number.isNaN(parsed) ? value : parsed
}
</script>

<style scoped>
.register-provider-card {
  display: grid;
  gap: 14px;
}

.register-provider-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.register-provider-title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 650;
  color: hsl(var(--foreground));
}

.register-provider-message {
  margin-top: -2px;
}

.register-provider-section {
  display: grid;
  gap: 10px;
}

.register-provider-section--soft {
  border: 1px solid hsl(var(--border) / 0.82);
  border-radius: 12px;
  background: hsl(var(--muted) / 0.16);
  padding: 12px;
}

.register-provider-section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  color: hsl(var(--muted-foreground));
  font-size: 11px;
  line-height: 1.25;
}

.register-provider-section-title::after {
  content: "";
  height: 1px;
  min-width: 24px;
  flex: 1;
  background: hsl(var(--border) / 0.72);
}

.register-provider-stack {
  display: grid;
  gap: 12px;
}

.register-preview-line {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.45;
  color: hsl(var(--muted-foreground));
}

.register-outlook-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.register-provider-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.register-provider-actions--left {
  justify-content: flex-start;
}

.register-field {
  display: grid;
  min-width: 0;
  gap: 7px;
}

.register-field--full {
  grid-column: 1 / -1;
}

.register-label {
  font-size: 12px;
  color: hsl(var(--muted-foreground));
}

.register-form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
  gap: 12px;
}

.register-form-grid--two {
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
}

.register-form-grid--three {
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
}

.register-checkbox-field {
  display: flex;
  min-height: 62px;
  align-items: end;
  padding-bottom: 8px;
}

.register-checkbox-field--compact {
  min-height: 0;
  align-items: center;
  padding-bottom: 0;
}

.register-textarea {
  min-height: 80px;
  width: 100%;
  resize: vertical;
  border: 1px solid hsl(var(--border));
  border-radius: 12px;
  background: hsl(var(--card));
  padding: 10px 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  line-height: 1.55;
  color: hsl(var(--foreground));
  outline: none;
}

.register-textarea--tall {
  min-height: 124px;
}

.register-textarea:focus {
  border-color: hsl(var(--ring));
  box-shadow: 0 0 0 2px hsl(var(--ring) / 0.14);
}

.register-textarea:disabled {
  cursor: not-allowed;
  opacity: 0.65;
}

.register-outlook-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.register-outlook-details {
  border-top: 1px solid hsl(var(--border) / 0.68);
  padding-top: 8px;
}

.register-outlook-details summary {
  cursor: pointer;
  width: fit-content;
  color: hsl(var(--muted-foreground));
  font-size: 12px;
  line-height: 1.4;
}

.register-outlook-details summary:hover {
  color: hsl(var(--foreground));
}

.register-outlook-detail-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding-top: 8px;
}

@media (max-width: 640px) {
  .register-provider-head {
    display: grid;
    align-items: start;
  }

  .register-provider-actions,
  .register-outlook-toolbar {
    grid-template-columns: 1fr;
    justify-content: flex-start;
  }

  .register-outlook-toolbar {
    display: grid;
  }
}
</style>
