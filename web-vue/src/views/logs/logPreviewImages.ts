import { panelMediaUrl } from '../../lib/panelMediaUrl.ts'

export type LogPreviewImage = {
  url: string
  title?: string
  filename?: string
  alt?: string
  broken?: boolean
}

function filenameFromPreviewUrl(url: string): string {
  const value = String(url || '').trim()
  if (!value) return '-'
  try {
    const parsed = new URL(value, 'https://local.invalid')
    return decodeURIComponent(parsed.pathname.split('/').pop() || value)
  } catch {
    return decodeURIComponent(value.split(/[/?#]/)[0]?.split('/').pop() || value)
  }
}

export function buildLogPreviewImages(
  item: { imageUrls?: readonly string[]; urls?: readonly string[] } | null | undefined,
  isPreviewBroken: (url: string) => boolean,
): LogPreviewImage[] {
  if (!item?.imageUrls?.length) return []
  const sourceUrls = item.urls || []
  return item.imageUrls.map((url, index) => {
    const sourceUrl = sourceUrls[index] || url
    const displayUrl = panelMediaUrl(url)
    return {
      url: displayUrl,
      title: sourceUrl,
      filename: filenameFromPreviewUrl(sourceUrl),
      alt: `日志结果图片 ${index + 1}`,
      broken: isPreviewBroken(displayUrl),
    }
  })
}
