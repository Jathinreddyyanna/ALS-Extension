import { create } from 'zustand'
import { scoreUrl } from '../detection/urlScorer'
import type { EmailAnalysisState, UrlScanResult } from '../types'

interface PopupStoreState {
  initialized: boolean
  isLoading: boolean
  error: string | null
  currentUrl: string
  currentDomain: string
  currentTabId: number | null
  scanResult: UrlScanResult | null
  emailState: EmailAnalysisState
  initialize: () => Promise<void>
  load: () => Promise<void>
  rescan: () => Promise<void>
  resetEmail: () => Promise<void>
}

const DEFAULT_EMAIL_STATE: EmailAnalysisState = {
  emailText: '',
  senderEmail: '',
  subject: '',
  links: [],
  attachmentNames: [],
  hasAttachments: false,
  riskScore: 0,
  riskLabel: 'safe',
  status: 'waiting',
  explanation: '',
  attackType: 'None',
  confidence: 0,
  isSpamFolder: false,
  signals: [],
  detectedPatterns: [],
}

function isSupportedUrl(url: string): boolean {
  return Boolean(url) &&
    !url.startsWith('chrome://') &&
    !url.startsWith('chrome-extension://') &&
    !url.startsWith('about:') &&
    !url.startsWith('devtools://')
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

function createFallbackResult(url: string): UrlScanResult {
  const local = scoreUrl(url)
  const confidence = Math.max(0.35, Math.min(0.82, 0.45 + (local.indicators.length * 0.08)))
  return {
    url,
    domain: extractDomain(url),
    riskScore: local.score,
    riskLevel: local.riskLevel,
    explanation: local.score <= 25
      ? 'This page looks low risk based on local domain and page checks.'
      : 'This page triggered local browser checks, so treat it with caution until a live scan completes.',
    aiExplanation: 'Built-in browser checks provided this explanation while the live backend scan was unavailable.',
    keyIndicators: local.indicators,
    positives: local.score <= 25 ? ['No major phishing indicators detected'] : [],
    warnings: local.score > 25 ? local.indicators : [],
    recommendedAction: local.score >= 76 ? 'block' : local.score >= 26 ? 'warn' : 'allow',
    confidence,
    category: 'unknown',
    categories: [],
    verdict: local.score >= 76 ? 'malicious' : local.score >= 26 ? 'suspicious' : 'safe',
    heuristic: local.score,
    dbRiskScore: 0,
    dbReportCount: 0,
    cached: false,
    aiDegraded: true,
    aiSource: 'heuristic',
    aiUsed: false,
    processedMs: 0,
    urlType: 'website',
    source: 'heuristic',
    activityLog: [],
  }
}

async function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  return tabs[0] ?? null
}

async function getStoredEmailState(): Promise<EmailAnalysisState> {
  try {
    const stored = await chrome.storage.local.get('emailAnalysisState')
    return { ...DEFAULT_EMAIL_STATE, ...(stored.emailAnalysisState ?? {}) } as EmailAnalysisState
  } catch {
    return DEFAULT_EMAIL_STATE
  }
}

let listenersRegistered = false

export const useStore = create<PopupStoreState>((set, get) => ({
  initialized: false,
  isLoading: true,
  error: null,
  currentUrl: '',
  currentDomain: '',
  currentTabId: null,
  scanResult: null,
  emailState: DEFAULT_EMAIL_STATE,

  initialize: async () => {
    if (!listenersRegistered) {
      chrome.runtime.onMessage.addListener((message) => {
        if (!message || typeof message !== 'object') return

        if (message.type === 'SCAN_UPDATED' && message.payload) {
          set({ scanResult: message.payload as UrlScanResult, isLoading: false, error: null })
        }

        if (message.type === 'EMAIL_STATE_UPDATED' && message.payload) {
          set({ emailState: { ...DEFAULT_EMAIL_STATE, ...(message.payload as Partial<EmailAnalysisState>) } })
        }
      })

      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== 'local' || !changes.emailAnalysisState) return
        set({
          emailState: {
            ...DEFAULT_EMAIL_STATE,
            ...((changes.emailAnalysisState.newValue ?? {}) as Partial<EmailAnalysisState>),
          },
        })
      })

      listenersRegistered = true
    }

    const emailState = await getStoredEmailState()
    set({ initialized: true, emailState })
    await get().load()
  },

  load: async () => {
    set({ isLoading: true, error: null })
    const tab = await getActiveTab()
    const url = tab?.url ?? ''
    const tabId = typeof tab?.id === 'number' ? tab.id : null
    const domain = extractDomain(url)

    if (!isSupportedUrl(url)) {
      set({
        currentUrl: url,
        currentDomain: domain,
        currentTabId: tabId,
        scanResult: null,
        isLoading: false,
        error: 'This page cannot be scanned in the popup.',
      })
      return
    }

    set({ currentUrl: url, currentDomain: domain, currentTabId: tabId })

    try {
      const result = await new Promise<UrlScanResult | null>((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'GET_SCAN_DATA', tabId },
          (response: UrlScanResult | null) => {
            if (chrome.runtime.lastError) {
              resolve(null)
              return
            }
            resolve(response)
          }
        )
      })

      set({
        scanResult: result ?? createFallbackResult(url),
        isLoading: false,
        error: result ? null : 'Live scan unavailable. Showing local browser analysis instead.',
      })
    } catch {
      set({
        scanResult: createFallbackResult(url),
        isLoading: false,
        error: 'Live scan unavailable. Showing local browser analysis instead.',
      })
    }
  },

  rescan: async () => {
    const { currentTabId } = get()
    if (currentTabId == null) {
      await get().load()
      return
    }

    set({ isLoading: true, error: null })
    await new Promise<void>((resolve) => {
      chrome.runtime.sendMessage({ type: 'RESCAN_TAB', tabId: currentTabId }, () => {
        void chrome.runtime.lastError
        resolve()
      })
    })
    await get().load()
  },

  resetEmail: async () => {
    await new Promise<void>((resolve) => {
      chrome.runtime.sendMessage({ type: 'RESET_EMAIL_STATE' }, () => {
        void chrome.runtime.lastError
        resolve()
      })
    })
    set({ emailState: DEFAULT_EMAIL_STATE })
  },
}))
