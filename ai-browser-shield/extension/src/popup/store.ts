import { create } from 'zustand'
import type { ThreatEvent, CommunityReport } from '../types'
import { getRecentFeed, submitReport, getDomainScore } from '../api/client'
import { scoreUrlCached } from '../detection/urlScorer'

type EmailRiskLabel = 'safe' | 'suspicious' | 'dangerous'
type EmailStatus = 'waiting' | 'analyzing' | 'ready' | 'deep_scanning'

type EmailAnalysisState = {
  emailText: string
  riskScore: number
  riskLabel: EmailRiskLabel
  status: EmailStatus
  explanation?: string
  attackType?: string
  confidence?: number
  isSpamFolder?: boolean
  signals?: Array<{ name: string; score: number }>
  detectedPatterns?: string[]
}

const DEFAULT_EMAIL_STATE: EmailAnalysisState = {
  emailText: '',
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

async function readHistory(): Promise<ThreatEvent[]> {
  return new Promise(resolve => {
    chrome.storage.local.get('threatHistory', (r) => resolve(r.threatHistory || []))
  })
}

async function wipeHistory(): Promise<void> {
  return new Promise(resolve => chrome.storage.local.remove('threatHistory', resolve))
}

interface StoreState {
  history: ThreatEvent[]
  feed: CommunityReport[]
  currentScore: number | null
  currentDomain: string
  activeTab: 'score' | 'email' | 'history' | 'feed' | 'report'
  isLoading: boolean
  reportSuccess: boolean
  emailText: string
  emailRiskScore: number
  emailRiskLabel: EmailRiskLabel
  emailStatus: EmailStatus
  emailExplanation: string
  emailAttackType: string
  emailConfidence: number
  emailIsSpamFolder: boolean
  emailSignals: Array<{ name: string; score: number }>
  emailDetectedPatterns: string[]
  loadAll: () => Promise<void>
  setTab: (tab: StoreState['activeTab']) => void
  submitUserReport: (data: { category: string; description: string }) => Promise<void>
  clearAll: () => Promise<void>
}

export const useStore = create<StoreState>((set, get) => {
  chrome.storage.local.get(['emailAnalysisState'], (result) => {
    const state = (result.emailAnalysisState || DEFAULT_EMAIL_STATE) as EmailAnalysisState
    set({
      emailText: state.emailText || '',
      emailRiskScore: state.riskScore || 0,
      emailRiskLabel: state.riskLabel || 'safe',
      emailStatus: state.status || 'waiting',
      emailExplanation: state.explanation || '',
      emailAttackType: state.attackType || 'None',
      emailConfidence: state.confidence || 0,
      emailIsSpamFolder: Boolean(state.isSpamFolder),
      emailSignals: state.signals || [],
      emailDetectedPatterns: state.detectedPatterns || [],
    })
  })

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes.emailAnalysisState) return
    const state = (changes.emailAnalysisState.newValue || DEFAULT_EMAIL_STATE) as EmailAnalysisState
    set({
      emailText: state.emailText || '',
      emailRiskScore: state.riskScore || 0,
      emailRiskLabel: state.riskLabel || 'safe',
      emailStatus: state.status || 'waiting',
      emailExplanation: state.explanation || '',
      emailAttackType: state.attackType || 'None',
      emailConfidence: state.confidence || 0,
      emailIsSpamFolder: Boolean(state.isSpamFolder),
      emailSignals: state.signals || [],
      emailDetectedPatterns: state.detectedPatterns || [],
    })
  })

  return {
    history: [],
    feed: [],
    currentScore: null,
    currentDomain: '',
    activeTab: 'score',
    isLoading: false,
    reportSuccess: false,
    emailText: '',
    emailRiskScore: 0,
    emailRiskLabel: 'safe',
    emailStatus: 'waiting',
    emailExplanation: '',
    emailAttackType: 'None',
    emailConfidence: 0,
    emailIsSpamFolder: false,
    emailSignals: [],
    emailDetectedPatterns: [],

    loadAll: async () => {
    set({ isLoading: true })
    let domain = ''
    let currentScore: number | null = null
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tabs[0]?.url || ''
      domain = new URL(url).hostname

      // Primary source: local scorer (works offline / no-db and uses current URL)
      if (url && /^https?:\/\//.test(url)) {
        currentScore = scoreUrlCached(url).score
      }

      const cached: { score: number; ts: number } | null = await new Promise(resolve => {
        chrome.storage.local.get('score:' + domain, r => resolve(r['score:' + domain] || null))
      })
      if (cached && Date.now() - cached.ts < 600000) {
        currentScore = cached.score
      } else if (currentScore === null) {
        // Fallback: backend domain score (used only if URL couldn't be scored locally)
        const scoreData = await getDomainScore(domain)
        currentScore = scoreData?.riskScore ?? null
      }
    } catch {}
    const [history, feed] = await Promise.all([readHistory(), getRecentFeed()])
    set({ history, feed, currentDomain: domain, currentScore, isLoading: false })
    },

    setTab: (tab) => set({ activeTab: tab }),

    submitUserReport: async ({ category, description }) => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tabs[0]?.url || ''
      await submitReport({ url, category: category as any, description })
      set({ reportSuccess: true })
      setTimeout(() => set({ reportSuccess: false, activeTab: 'history' }), 2000)
    },

    clearAll: async () => {
      await wipeHistory()
      set({ history: [] })
    },
  }
})
