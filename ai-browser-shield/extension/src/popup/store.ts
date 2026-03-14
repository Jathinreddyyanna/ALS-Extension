import { create } from 'zustand'
import type { CommunityReport, EmailAnalysis, EmailSnapshot, ThreatEvent } from '../types'
import { getDomainScore, getRecentFeed, submitReport } from '../api/client'
import { scoreUrl } from '../detection/urlScorer'

async function readHistory(): Promise<ThreatEvent[]> {
  return new Promise((resolve) => {
    chrome.storage.local.get('threatHistory', (result) => resolve(result.threatHistory || []))
  })
}

async function wipeHistory(): Promise<void> {
  return new Promise((resolve) => chrome.storage.local.remove('threatHistory', resolve))
}

interface StoreState {
  history: ThreatEvent[]
  feed: CommunityReport[]
  currentScore: number | null
  currentDomain: string
  activeTab: 'score' | 'email' | 'history' | 'feed' | 'report'
  emailAnalysis: EmailAnalysis | null
  emailSnapshot: EmailSnapshot | null
  emailProcessing: boolean
  isLoading: boolean
  reportSuccess: boolean
  loadAll: () => Promise<void>
  setTab: (tab: StoreState['activeTab']) => void
  submitUserReport: (data: { category: string; description: string }) => Promise<void>
  clearAll: () => Promise<void>
}

export const useStore = create<StoreState>((set) => ({
  history: [],
  feed: [],
  currentScore: null,
  currentDomain: '',
  activeTab: 'score',
  emailAnalysis: null,
  emailSnapshot: null,
  emailProcessing: false,
  isLoading: false,
  reportSuccess: false,

  loadAll: async () => {
    set({ isLoading: true })
    let domain = ''
    let currentScore: number | null = null

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tabs[0]?.url || ''
      domain = new URL(url).hostname
      const cached: { score: number; ts: number } | null = await new Promise((resolve) => {
        chrome.storage.local.get('score:' + domain, (result) => resolve(result['score:' + domain] || null))
      })

      if (cached && Date.now() - cached.ts < 600000) {
        currentScore = cached.score
      } else {
        const scoreData = await getDomainScore(domain)
        currentScore = scoreData?.riskScore ?? null
        if (currentScore === null && url) {
          currentScore = scoreUrl(url).score
        }
      }
    } catch {}

    const [history, feed, emailState] = await Promise.all([
      readHistory(),
      getRecentFeed(),
      new Promise<{ currentEmailAnalysis: EmailAnalysis | null; lastEmailSnapshot: EmailSnapshot | null; processingState: boolean }>((resolve) => {
        chrome.storage.local.get(['currentAnalysis', 'lastEmail', 'currentEmailAnalysis', 'lastEmailSnapshot', 'processingState'], (result) => {
          resolve({
            currentEmailAnalysis: result.currentAnalysis || result.currentEmailAnalysis || null,
            lastEmailSnapshot: result.lastEmail || result.lastEmailSnapshot || null,
            processingState: !!result.processingState,
          })
        })
      }),
    ])

    set({
      history,
      feed,
      currentDomain: domain,
      currentScore,
      emailAnalysis: emailState.currentEmailAnalysis,
      emailSnapshot: emailState.lastEmailSnapshot,
      emailProcessing: emailState.processingState,
      isLoading: false,
    })
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
}))
