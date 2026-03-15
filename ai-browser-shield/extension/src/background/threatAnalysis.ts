import type { SignalMap } from '../types'
import type { PopupAndRedirectAnalysis } from '../detection/popupRedirectTracker'
import { createPopupAnalysisPayload } from '../detection/popupRedirectTracker'

export interface WebThreatAnalysisPayload {
  url: string
  hostname: string
  path: string
  urlSignals: SignalMap
  popupRedirect?: ReturnType<typeof createPopupAnalysisPayload>
}

export function createWebThreatPayload(
  url: string,
  urlSignals: SignalMap,
  popupAnalysis?: PopupAndRedirectAnalysis
): WebThreatAnalysisPayload {
  let hostname = ''
  let path = ''

  try {
    const u = new URL(url)
    hostname = u.hostname
    path = `${u.pathname}${u.search}`
  } catch {
    hostname = ''
    path = ''
  }

  const payload: WebThreatAnalysisPayload = {
    url,
    hostname,
    path,
    urlSignals,
  }

  if (popupAnalysis) {
    payload.popupRedirect = createPopupAnalysisPayload(popupAnalysis)
  }

  return payload
}
