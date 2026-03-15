import { create } from 'zustand'
import type { ThreatEvent, CommunityReport, TrackerSessionStats, TrackerTabStats } from '../types'
import { getRecentFeed, submitReport, getThreatEvents, getDomainScore, scanUrl } from '../api/client'
import { getSessionStats, getTabStats } from '../detection/trackerEngine'
import { scoreUrl } from '../detection/urlScorer'

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
  currentRiskLevel: string
  reportCount: number
  blockedCounts: { ads: number; trackers: number; cryptominers: number }
  currentDomain: string
  currentTabId: number | null
  currentExplanation: string | null
  currentSource: string | null
  currentCommunityReports24h: number
  trackerSessionStats: TrackerSessionStats | null
  trackerTabStats: TrackerTabStats | null
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
  currentRiskLevel: 'LOW',
  reportCount: 0,
  blockedCounts: { ads: 0, trackers: 0, cryptominers: 0 },
  currentDomain: '',
  currentTabId: null,
  currentExplanation: null,
  currentSource: null,
  currentCommunityReports24h: 0,
  trackerSessionStats: null,
  trackerTabStats: null,
  activeTab: 'score',
  isLoading: false,
  reportSuccess: false,

  loadAll: async () => {
    set({ isLoading: true })
    let domain = ''
    let activeTabId: number | null = null
    let currentScore: number | null = null
    let currentRiskLevel = 'LOW'
    let reportCount = 0
    let blockedCounts = { ads: 0, trackers: 0, cryptominers: 0 }
    let currentExplanation: string | null = null
    let currentSource: string | null = null
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tabs[0]?.url || ''
      activeTabId = typeof tabs[0]?.id === 'number' ? tabs[0]!.id! : null
      if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) {
        set({
          isLoading: false,
          currentDomain: '',
          currentScore: null,
          currentRiskLevel: 'LOW',
          reportCount: 0,
          blockedCounts,
        })
        return
      }

      domain = new URL(url).hostname
      const localHistory = await readHistory()
      const latest = localHistory.find(e => e.domain === domain && e.eventType === 'url_threat')

      blockedCounts = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_BLOCKED_COUNTS' }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ ads: 0, trackers: 0, cryptominers: 0 })
            return
          }
          resolve(response ?? { ads: 0, trackers: 0, cryptominers: 0 })
        })
      })

      if (latest) {
        const cached = await new Promise<{ score: number; ts: number } | null>((resolve) => {
          chrome.storage.local.get(`score:${domain}`, (r) => resolve(r[`score:${domain}`] || null))
        })

        currentScore = cached?.score ?? latest.riskScore
        currentExplanation = latest.aiExplanation || null
        currentSource = latest.source || null
      } else {
        let scoreData = null
        try {
          const cached = await new Promise<{ score: number; ts: number } | null>((resolve) => {
            chrome.storage.local.get(`score:${domain}`, (r) => resolve(r[`score:${domain}`] || null))
          })

          if (cached && Date.now() - cached.ts < 300000) {
            currentScore = cached.score
            currentSource = 'backend'
          } else {
            scoreData = await getDomainScore(domain)
            currentScore = scoreData?.riskScore ?? null
            reportCount = scoreData?.reportCount ?? 0
            currentSource = scoreData ? 'db' : null

            if (currentScore === null) {
              const local = scoreUrl(url)
              const backendScan = await scanUrl(url, local.signals)
              if (backendScan) {
                currentScore = typeof backendScan.riskScore === 'number' ? backendScan.riskScore : local.score
                currentExplanation = backendScan.explanation || null
                currentSource = 'backend'
                chrome.storage.local.set({
                  [`score:${domain}`]: { score: currentScore, ts: Date.now() },
                })
              } else {
                currentScore = local.score
                currentExplanation = null
                currentSource = 'heuristic'
              }
            }
          }
        } catch {
          currentScore = null
          currentSource = null
        }
        reportCount = scoreData?.reportCount ?? reportCount
      }

      if (currentScore !== null) {
        currentRiskLevel =
          currentScore >= 75 ? 'CRITICAL'
          : currentScore >= 50 ? 'HIGH'
          : currentScore >= 30 ? 'MEDIUM'
          : 'LOW'
      }
    } catch {
      domain = ''
      currentScore = null
      currentRiskLevel = 'LOW'
      reportCount = 0
      currentExplanation = null
      currentSource = null
    }
    const [localHistory, backendEvents, feed, trackerSessionStats, trackerTabStats] = await Promise.all([
      readHistory(),
      domain ? getThreatEvents(domain) : Promise.resolve([]),
      getRecentFeed(),
      getSessionStats(),
      activeTabId != null ? getTabStats(activeTabId) : Promise.resolve(null),
    ])

    const mergedHistory = [...localHistory, ...backendEvents].sort((a, b) => b.timestamp - a.timestamp)

    const now = Date.now()
    const DAY_MS = 24 * 60 * 60 * 1000
    const reportsForDomain24h = feed
      .filter((item) => item.domain === domain && now - new Date(item.lastSeen).getTime() < DAY_MS)
      .reduce((sum, item) => sum + (item.reports || 0), 0)

    set({
      history: mergedHistory,
      feed,
      currentDomain: domain,
      currentTabId: activeTabId,
      currentScore,
      currentRiskLevel,
      reportCount,
      blockedCounts,
      currentExplanation,
      currentSource,
      currentCommunityReports24h: reportsForDomain24h,
      trackerSessionStats,
      trackerTabStats,
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
