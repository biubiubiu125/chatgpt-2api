export interface StudioSlotFailure {
  index: number
  message: string
}

export interface StudioImageSlot<T> {
  index: number
  state: 'image' | 'pending' | 'failed'
  asset: T | null
  message: string
}

function requestedCount(value: number) {
  if (!Number.isInteger(value)) return 1
  return Math.min(4, Math.max(1, value))
}

function slotIndex(value: unknown) {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : null
}

export function parseSlotFailureText(text: string): StudioSlotFailure[] {
  const source = text.trim()
  if (!source) return []
  const found: StudioSlotFailure[] = []
  for (const match of source.matchAll(/第\s*(\d+)\s*张失败：([^；]*)/g)) {
    const index = Number(match[1])
    const message = String(match[2] || '').trim()
    if (!Number.isInteger(index) || index < 1 || !message) continue
    found.push({ index, message })
  }
  return found
}

export function buildStudioImageSlots<T extends { slot_index?: number | null }>(input: {
  requestedCount: number
  terminal: boolean
  assets: readonly T[]
  slotFailures: readonly StudioSlotFailure[]
  publicError?: string
}): StudioImageSlot<T>[] {
  const count = requestedCount(input.requestedCount)
  const explicit = input.slotFailures.filter((item) => item.index >= 1 && item.index <= count && item.message.trim())
  const failures = explicit.length ? explicit : parseSlotFailureText(input.publicError || '').filter((item) => item.index <= count)
  const failedIndexes = new Set(failures.map((item) => item.index))
  const failureMessage = new Map(failures.map((item) => [item.index, item.message.trim()]))
  if (input.terminal && failedIndexes.size === 0 && input.assets.length < count) {
    for (let index = input.assets.length + 1; index <= count; index += 1) {
      failedIndexes.add(index)
    }
  }

  const placed = new Map<number, T>()
  const unindexed: T[] = []
  input.assets.forEach((asset) => {
    const index = slotIndex(asset.slot_index)
    if (index && index <= count && !failedIndexes.has(index) && !placed.has(index)) {
      placed.set(index, asset)
      return
    }
    unindexed.push(asset)
  })
  const free = Array.from({ length: count }, (_, offset) => offset + 1)
    .filter((index) => !failedIndexes.has(index) && !placed.has(index))
  unindexed.forEach((asset, index) => {
    const slot = free[index]
    if (slot) placed.set(slot, asset)
  })

  const fallback = String(input.publicError || '').trim()
  return Array.from({ length: count }, (_, offset) => {
    const index = offset + 1
    const asset = placed.get(index) || null
    if (asset) return { index, state: 'image' as const, asset, message: '' }
    if (failedIndexes.has(index) || input.terminal) {
      return {
        index,
        state: 'failed' as const,
        asset: null,
        message: failureMessage.get(index) || fallback,
      }
    }
    return { index, state: 'pending' as const, asset: null, message: '' }
  })
}
