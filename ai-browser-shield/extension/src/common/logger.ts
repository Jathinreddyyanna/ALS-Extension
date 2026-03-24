export type PipelineTag = 'EMAIL' | 'URL' | 'REDIRECT' | 'DOWNLOAD' | 'AI' | 'SYSTEM'

const DIAGNOSTIC_LOGS_ENABLED = (import.meta.env.VITE_DIAGNOSTIC_LOGS ?? 'false') === 'true'

function prefix(tag: PipelineTag): string {
  return `[AI Shield][${tag}]`
}

export function logInfo(tag: PipelineTag, message: string, ...args: unknown[]): void {
  if (!DIAGNOSTIC_LOGS_ENABLED) return
  console.info(prefix(tag), message, ...args)
}

export function logWarn(tag: PipelineTag, message: string, ...args: unknown[]): void {
  if (!DIAGNOSTIC_LOGS_ENABLED) return
  console.warn(prefix(tag), message, ...args)
}

export function logError(tag: PipelineTag, message: string, ...args: unknown[]): void {
  if (!DIAGNOSTIC_LOGS_ENABLED) return
  console.error(prefix(tag), message, ...args)
}