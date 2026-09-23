import { ref } from 'vue'
import { notifyAuthFailure } from '@/api/client'
import type { LegacyRegisterConfig } from '@/api/register'
import type { PageRuntime } from '@/composables/usePageRuntime'

export type RegisterLiveRuntimeInput = {
  runtime: PageRuntime
  getAuthToken: () => string
  loadConfig: (silent?: boolean) => Promise<void>
  applyRemoteConfig: (config: LegacyRegisterConfig) => boolean
  isTaskEnabled: () => boolean
}

const POLL_INTERVAL_KEY = 'register:poll'

function eventsBaseUrl() {
  return String(import.meta.env.VITE_API_URL || '').replace(/\/$/, '')
}

export function useRegisterLiveRuntime(input: RegisterLiveRuntimeInput) {
  const streamController = ref<AbortController | null>(null)

  function stopLiveUpdates() {
    if (streamController.value) {
      streamController.value.abort()
      streamController.value = null
    }
  }

  function stopPolling() {
    input.runtime.clearInterval(POLL_INTERVAL_KEY)
  }

  function startPolling() {
    stopPolling()
    if (!input.runtime.canRun.value) return
    input.runtime.setInterval(POLL_INTERVAL_KEY, 2000, async () => {
      if (!input.runtime.canRun.value) {
        stopPolling()
        return
      }
      await input.loadConfig(true)
      if (!input.isTaskEnabled()) {
        stopPolling()
      }
    })
  }

  async function startLiveUpdates() {
    stopLiveUpdates()
    if (!input.runtime.canRun.value) return
    const token = input.getAuthToken()
    if (!token) {
      startPolling()
      return
    }
    const controller = new AbortController()
    streamController.value = controller
    try {
      const response = await fetch(`${eventsBaseUrl()}/api/register/events`, {
        method: 'POST',
        headers: {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${token}`,
        },
        signal: controller.signal,
      })
      if (!response.ok || !response.body) {
        notifyAuthFailure(response.status)
        throw new Error(`register event stream failed: ${response.status}`)
      }
      stopPolling()
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (!controller.signal.aborted && input.runtime.canRun.value) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const events = buffer.split('\n\n')
        buffer = events.pop() || ''
        for (const event of events) {
          let eventName = 'message'
          for (const line of event.split('\n')) {
            if (line.startsWith('event:')) {
              eventName = line.slice(6).trim() || 'message'
              continue
            }
          }
          if (eventName !== 'message') continue
          for (const line of event.split('\n')) {
            if (!line.startsWith('data:')) continue
            try {
              input.applyRemoteConfig(JSON.parse(line.slice(5).trim()) as LegacyRegisterConfig)
            } catch {
              // Ignore malformed event payloads and keep the stream alive.
            }
          }
        }
      }
      if (!controller.signal.aborted && input.runtime.canRun.value) {
        startPolling()
      }
    } catch {
      if (!controller.signal.aborted && input.runtime.canRun.value) {
        startPolling()
      }
    } finally {
      if (streamController.value === controller) {
        streamController.value = null
      }
    }
  }

  function stop() {
    stopLiveUpdates()
    stopPolling()
  }

  return {
    streamController,
    startLiveUpdates,
    stopLiveUpdates,
    startPolling,
    stopPolling,
    stop,
  }
}
