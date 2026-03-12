import { create } from 'zustand'
import type { ThreatEvent, CommunityReport } from '../types'
import { getRecentFeed, submitReport, getDomainScore } from '../api/client'

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
  activeTab: 'score' | 'history' | 'feed' | 'report'
  isLoading: boolean
  reportSuccess: boolean
  loadAll: () => Promise<void>
  setTab: (tab: StoreState['activeTab']) => void
  submitUserReport: (data: { category: string; description: string }) => Promise<void>
  clearAll: () => Promise<void>
}

export const useStore = create<StoreState>((set, get) => ({
  history: [],
  feed: [],
  currentScore: null,
  currentDomain: '',
  activeTab: 'score',
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
      const cached: { score: number; ts: number } | null = await new Promise(resolve => {
        chrome.storage.local.get('score:' + domain, r => resolve(r['score:' + domain] || null))
      })
      if (cached && Date.now() - cached.ts < 600000) {
        currentScore = cached.score
      } else {
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
}))
