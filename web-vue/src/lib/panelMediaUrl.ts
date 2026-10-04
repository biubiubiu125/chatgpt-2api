function cleanMediaUrl(value: unknown): string {
  return String(value || '').trim()
}

function panelOrigin(): string {
  if (typeof window === 'undefined') return ''
  return window.location.origin
}

const PANEL_MEDIA_MOUNTS = ['/image-thumbnails', '/images'] as const

/** Root mount, even when a public prefix left an extra path in front. */
export function panelMediaMountPath(pathname: string): string {
  const path = String(pathname || '')
  if (!path.startsWith('/')) return ''
  for (const mount of PANEL_MEDIA_MOUNTS) {
    if (path === mount || path.startsWith(`${mount}/`)) return path
    const nested = `${mount}/`
    const index = path.indexOf(nested)
    if (index > 0) return path.slice(index)
    if (
      path.endsWith(mount)
      && path.length > mount.length
      && path.charAt(path.length - mount.length - 1) === '/'
    ) {
      return mount
    }
  }
  return ''
}

export function panelMediaRelativeUrl(url: string, keepHash = false): string {
  const raw = cleanMediaUrl(url)
  if (!raw || raw.startsWith('data:') || raw.startsWith('blob:')) return ''
  let parsed: URL
  try {
    parsed = new URL(raw, panelOrigin() || 'https://local.invalid')
  } catch {
    return ''
  }
  const mountPath = panelMediaMountPath(parsed.pathname)
  if (!mountPath) return ''
  // R2 and other remote files also use an /images/ path. Only this site's
  // signed media (exp + sig) is rewritten onto the open panel.
  const remote = /^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('//')
  if (remote && !(parsed.searchParams.has('exp') && parsed.searchParams.has('sig'))) return ''
  return `${mountPath}${parsed.search}${keepHash ? parsed.hash : ''}`
}

function unsignedLocalImageUrl(path: unknown): string {
  const cleaned = cleanMediaUrl(path).replace(/^\/+/, '')
  if (!cleaned) return ''
  return `/images/${cleaned.split('/').filter(Boolean).map((part) => encodeURIComponent(part)).join('/')}`
}

/** Signed panel URL first. A bare path has no signature and is only a fallback. */
export function panelImageAssetSource(asset: { url?: unknown; path?: unknown } | null | undefined): string {
  const rewritten = panelMediaUrl(cleanMediaUrl(asset?.url))
  if (rewritten) return rewritten
  return unsignedLocalImageUrl(asset?.path)
}

/** Keep signed panel images on the site that is open now. Remote https stays unchanged. */
export function panelMediaUrl(url: string): string {
  const raw = cleanMediaUrl(url)
  if (!raw || raw.startsWith('data:') || raw.startsWith('blob:')) return raw
  const relative = panelMediaRelativeUrl(raw)
  if (!relative) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith('//')) return raw
    return raw
  }
  const origin = panelOrigin()
  return origin ? `${origin}${relative}` : relative
}
