/// <reference types="vite/client" />

declare module '@contracts/chrome146.json' {
  const value: { userAgent: string }
  export default value
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, any>
  export default component
}
